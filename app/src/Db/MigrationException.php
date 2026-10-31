<?php

declare(strict_types=1);

namespace Mailhost\Db;

use RuntimeException;

/** A migration cannot be applied, or the applied history no longer matches the files. */
final class MigrationException extends RuntimeException
{
}
