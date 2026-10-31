<?php

declare(strict_types=1);

namespace Mailhost\Tests\Unit;

use Mailhost\Cli\EnvFile;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class EnvFileTest extends TestCase
{
    /** @var list<string> */
    private array $tempFiles = [];

    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        $this->tempFiles = [];
    }

    private function tempEnv(string $contents, int $mode = 0600): string
    {
        $path = tempnam(sys_get_temp_dir(), 'envfile');
        $this->assertNotFalse($path);
        $this->tempFiles[] = $path;
        file_put_contents($path, $contents);
        chmod($path, $mode);

        return $path;
    }

    public function test_parses_pairs(): void
    {
        $path = $this->tempEnv("A=1\n# c\n\nB = two \nC=\"q v\"\n");

        $this->assertSame(['A' => '1', 'B' => 'two', 'C' => 'q v'], EnvFile::load($path));
    }

    public function test_rejects_world_readable(): void
    {
        $path = $this->tempEnv("A=1\n", 0644);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/world-readable/');

        EnvFile::load($path);
    }

    public function test_permission_check_sees_chmod_after_an_earlier_load(): void
    {
        $path = $this->tempEnv("A=1\n");
        $this->assertSame(['A' => '1'], EnvFile::load($path));

        chmod($path, 0644);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/world-readable/');

        EnvFile::load($path);
    }

    public function test_rejects_malformed_line(): void
    {
        $path = $this->tempEnv("A=1\nNOVALUE\n");

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/line 2/');

        EnvFile::load($path);
    }

    public function test_missing_file_throws(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/not found/');

        EnvFile::load(sys_get_temp_dir() . '/envfile-does-not-exist-' . bin2hex(random_bytes(4)));
    }
}
