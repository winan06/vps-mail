<?php

declare(strict_types=1);

namespace Mailhost\Db;

use InvalidArgumentException;

/**
 * Splits a migration file into single statements.
 *
 * A statement ends at a line whose right-trimmed text ends in ";". Lines whose
 * trimmed text starts with "--" are dropped. Semicolons elsewhere in a line are
 * part of the statement, and stored procedures or triggers are not supported.
 */
final class SqlSplitter
{
    /**
     * @return list<string> statements without their terminating semicolon
     *
     * @throws InvalidArgumentException when the input ends inside a statement
     */
    public static function split(string $sql): array
    {
        $statements = [];
        $current = [];

        foreach (preg_split('/\R/', $sql) as $line) {
            if (str_starts_with(trim($line), '--')) {
                continue;
            }

            $current[] = $line;

            if (str_ends_with(rtrim($line), ';')) {
                $statement = trim(substr(rtrim(implode("\n", $current)), 0, -1));
                if ($statement !== '') {
                    $statements[] = $statement;
                }
                $current = [];
            }
        }

        $rest = trim(implode("\n", $current));
        if ($rest !== '') {
            throw new InvalidArgumentException(
                'Unterminated statement (missing ";" at end of line): ' . substr($rest, 0, 60)
            );
        }

        return $statements;
    }
}
