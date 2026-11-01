<?php

declare(strict_types=1);

namespace Mailhost\Tests\Integration;

/**
 * DbTestCase refuses a server that has the production database, because the integration tests
 * re-provision the service accounts server-wide. The probe uses a scratch database name in place
 * of "mailhost", so this test never creates or drops a real one.
 */
final class SharedServerGuardTest extends DbTestCase
{
    private const PROBE = 'mailhost_guard_probe';
    private const OVERRIDE = 'MAILHOST_TEST_ALLOW_SHARED_SERVER';

    private string|false $savedOverride = false;

    protected function setUp(): void
    {
        parent::setUp();

        $this->savedOverride = getenv(self::OVERRIDE);
        putenv(self::OVERRIDE);
        $this->dropProbe();
    }

    protected function tearDown(): void
    {
        $this->dropProbe();
        putenv($this->savedOverride === false ? self::OVERRIDE : self::OVERRIDE . '=' . $this->savedOverride);

        parent::tearDown();
    }

    private function dropProbe(): void
    {
        $this->rootPdo(false)->exec('DROP DATABASE IF EXISTS `' . self::PROBE . '`');
    }

    private function createProbe(): void
    {
        $this->rootPdo(false)->exec('CREATE DATABASE `' . self::PROBE . '`');
    }

    public function test_server_without_the_production_database_is_accepted(): void
    {
        $this->assertNull($this->sharedServerRefusal(self::PROBE));
    }

    public function test_server_with_the_production_database_is_refused_with_the_reason(): void
    {
        $this->createProbe();

        $message = $this->sharedServerRefusal(self::PROBE);

        $this->assertNotNull($message);
        $this->assertStringContainsString('`' . self::PROBE . '`', $message);
        $this->assertStringContainsString('mail_ro', $message, 'the message must say which accounts would be overwritten');
        $this->assertStringContainsString(self::OVERRIDE . '=1', $message, 'the message must name the override');
    }

    public function test_override_allows_a_shared_server(): void
    {
        $this->createProbe();

        putenv(self::OVERRIDE . '=1');
        $this->assertNull($this->sharedServerRefusal(self::PROBE));

        putenv(self::OVERRIDE . '=yes');
        $this->assertNotNull($this->sharedServerRefusal(self::PROBE), 'only the exact value 1 overrides');
    }
}
