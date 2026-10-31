<?php

declare(strict_types=1);

namespace Mailhost\Cli;

use RuntimeException;

/**
 * Loads KEY=value pairs from a root-managed env file.
 *
 * Blank lines and lines starting with "#" are ignored. Keys match
 * /^[A-Z][A-Z0-9_]*$/, whitespace around the key, "=" and value is trimmed, and
 * a value wrapped in matching single or double quotes is unwrapped. The file must
 * not be world-readable because it holds database credentials.
 */
final class EnvFile
{
    /**
     * @return array<string,string>
     *
     * @throws RuntimeException when the file is missing, unreadable, world-readable or malformed
     */
    public static function load(string $path): array
    {
        // PHP caches stat results per path, and that cache can hold a stale mode
        // after chmod(). The permission check must see the file's current mode.
        clearstatcache(true, $path);

        if (!is_file($path)) {
            throw new RuntimeException("Env file not found: $path");
        }

        $perms = fileperms($path);
        if ($perms === false) {
            throw new RuntimeException("Cannot read permissions of env file: $path");
        }
        if (($perms & 0o004) !== 0) {
            throw new RuntimeException(sprintf(
                'Env file %s is world-readable (mode %04o); run chmod 0600',
                $path,
                $perms & 0o777
            ));
        }

        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new RuntimeException("Cannot read env file: $path");
        }

        $values = [];
        foreach (preg_split('/\R/', $contents) as $index => $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }

            if (preg_match('/^([A-Z][A-Z0-9_]*)\s*=\s*(.*)$/', $line, $match) !== 1) {
                throw new RuntimeException(sprintf('Malformed line %d in env file %s', $index + 1, $path));
            }

            $values[$match[1]] = self::unquote($match[2]);
        }

        return $values;
    }

    private static function unquote(string $value): string
    {
        if (strlen($value) >= 2 && ($value[0] === '"' || $value[0] === "'") && str_ends_with($value, $value[0])) {
            return substr($value, 1, -1);
        }

        return $value;
    }
}
