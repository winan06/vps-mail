<?php

declare(strict_types=1);

namespace Mailhost\Tests\Unit;

use InvalidArgumentException;
use Mailhost\Db\SqlSplitter;
use PHPUnit\Framework\TestCase;

final class SqlSplitterTest extends TestCase
{
    public function test_splits_on_semicolon_at_line_end(): void
    {
        $this->assertSame(
            ['CREATE TABLE a (x INT)', 'CREATE TABLE b (y INT)'],
            SqlSplitter::split("CREATE TABLE a (x INT);\nCREATE TABLE b (y INT);\n")
        );
    }

    public function test_keeps_multiline_statement(): void
    {
        $this->assertCount(
            1,
            SqlSplitter::split("CREATE VIEW v AS\nSELECT 1\nUNION ALL\nSELECT 2;\n")
        );
    }

    public function test_strips_line_comments(): void
    {
        $this->assertSame(['SELECT 1'], SqlSplitter::split("-- note;\nSELECT 1;\n"));
    }

    public function test_semicolon_inside_line_is_kept(): void
    {
        $this->assertSame(
            ["INSERT INTO s VALUES ('a;b')"],
            SqlSplitter::split("INSERT INTO s VALUES ('a;b');\n")
        );
    }

    public function test_unterminated_statement_throws(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Unterminated statement/');

        SqlSplitter::split('SELECT 1');
    }
}
