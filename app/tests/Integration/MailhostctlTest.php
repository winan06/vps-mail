<?php

declare(strict_types=1);

namespace Mailhost\Tests\Integration;

use Mailhost\Db\Connection;

/**
 * Runs bin/mailhostctl as a child process against its own database, mailhost_cli_test.
 */
final class MailhostctlTest extends DbTestCase
{
    private const CLI_DATABASE = 'mailhost_cli_test';

    private ?string $dir = null;
    private string $envFile = '';

    protected function setUp(): void
    {
        parent::setUp();

        // Fails fast when the MAILHOST_TEST_* variables are missing.
        $env = $this->cliEnv();

        $dir = sys_get_temp_dir() . '/mailhostctl-' . bin2hex(random_bytes(6));
        $this->assertTrue(mkdir($dir . '/migrations', 0700, true));
        $this->dir = $dir;

        file_put_contents($dir . '/migrations/0001_a.sql', "CREATE TABLE IF NOT EXISTS a (x INT);\n");

        $this->envFile = $dir . '/db.env';
        file_put_contents($this->envFile, sprintf(
            "DB_HOST=%s\nDB_PORT=%s\nDB_ROOT_PASSWORD=%s\nDB_NAME=%s\n",
            $env['DB_HOST'],
            $env['DB_PORT'],
            $env['DB_ROOT_PASSWORD'],
            $env['DB_NAME']
        ));
        chmod($this->envFile, 0600);

        $this->dropCliDatabase();
    }

    protected function tearDown(): void
    {
        if ($this->dir !== null) {
            foreach (glob($this->dir . '/migrations/*') ?: [] as $file) {
                unlink($file);
            }
            @unlink($this->envFile);
            rmdir($this->dir . '/migrations');
            rmdir($this->dir);
            $this->dir = null;

            $this->dropCliDatabase();
        }

        parent::tearDown();
    }

    /** @return array<string,string> */
    private function cliEnv(): array
    {
        return array_replace($this->env(), ['DB_NAME' => self::CLI_DATABASE]);
    }

    private function dropCliDatabase(): void
    {
        Connection::root($this->cliEnv(), false)->exec('DROP DATABASE IF EXISTS `' . self::CLI_DATABASE . '`');
    }

    /** @return array{0:int,1:string,2:string} exit code, stdout, stderr */
    private function ctl(string ...$args): array
    {
        $process = proc_open(
            [dirname(__DIR__, 2) . '/bin/mailhostctl', ...$args],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            null,
            [
                'PATH' => getenv('PATH') ?: '/usr/local/bin:/usr/bin:/bin',
                'MAILHOST_DB_ENV' => $this->envFile,
                'MAILHOST_MIGRATIONS_DIR' => $this->dir . '/migrations',
            ]
        );
        $this->assertIsResource($process);

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return [proc_close($process), $stdout, $stderr];
    }

    public function test_cli_migrate_twice(): void
    {
        // The database does not exist yet: migrate must create it.
        [$code, $out, $err] = $this->ctl('migrate');
        $this->assertSame(0, $code, $err);
        $this->assertStringContainsString('Applied: 0001_a', $out);
        $this->assertSame('', $err);

        [$code, $out, $err] = $this->ctl('migrate');
        $this->assertSame(0, $code, $err);
        $this->assertSame("Nothing to migrate.\n", $out);
        $this->assertSame('', $err);
    }

    public function test_cli_status(): void
    {
        $this->ctl('migrate');

        [$code, $out, $err] = $this->ctl('migrate:status');
        $this->assertSame(0, $code, $err);
        $this->assertSame("0001_a  applied\n", $out);
        $this->assertSame('', $err);
    }

    public function test_cli_bad_env_exits_1(): void
    {
        chmod($this->envFile, 0644);

        [$code, $out, $err] = $this->ctl('migrate');
        $this->assertSame(1, $code);
        $this->assertSame('', $out);
        $this->assertMatchesRegularExpression('/world-readable/', $err);
    }

    public function test_cli_unknown_command_exits_1(): void
    {
        [$code, $out, $err] = $this->ctl('frobnicate');
        $this->assertSame(1, $code);
        $this->assertSame('', $out);
        $this->assertMatchesRegularExpression('/Usage:/', $err);
    }
}
