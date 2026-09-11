#!/usr/bin/env node

import {
    access,
    copyFile,
    mkdir,
    readdir,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function exists(filePath: string): Promise<boolean> {
    try {
        await access(filePath);
        return true;
    } catch {
        return false;
    }
}

/** Supabase's migration version format: `YYYYMMDDHHMMSS`, in UTC. */
function formatVersion(date: Date): string {
    return date.toISOString().replace(/\D/g, "").slice(0, 14);
}

function parseVersion(version: string): Date | undefined {
    const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/.exec(version);

    if (match === null) {
        return undefined;
    }

    const [year, month, day, hour, minute, second] = match.slice(1).map(Number) as [
        number, number, number, number, number, number,
    ];

    const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));

    return Number.isNaN(date.getTime()) ? undefined : date;
}

async function main() {
    const cwd = process.cwd();

    const targetDir = path.join(
        cwd,
        "supabase",
        "migrations",
    );

    // Depending on your build layout, you may need ../migrations or ../../migrations.
    const sourceDir = path.resolve(
        __dirname,
        "../supabase/migrations",
    );

    if (!(await exists(sourceDir))) {
        throw new Error(
            `Could not find packaged migrations at ${sourceDir}`,
        );
    }

    await mkdir(targetDir, { recursive: true });

    const migrations = (await readdir(sourceDir))
        .filter(file => file.endsWith(".sql"))
        .sort();

    if (migrations.length === 0) {
        console.log("No migrations found.");
        return;
    }

    // Copies are named `<timestamp>_supabase_auth_<original>`, so the original filename is
    // recoverable from whatever is already installed. Skipping those stops a re-run from
    // duplicating migrations under fresh timestamps -- the duplicates would apply a second
    // time and fail on `create type` / `create table` -- while still allowing an upgrade to
    // install migrations that a newer version of this package added.
    const marker = "_supabase_auth_";

    const existing = (await readdir(targetDir)).filter(file =>
        file.endsWith(".sql"),
    );

    const installed = new Set(
        existing
            .map(file => {
                const at = file.indexOf(marker);
                return at === -1
                    ? undefined
                    : file.slice(at + marker.length);
            })
            .filter((name): name is string => name !== undefined),
    );

    const pending = migrations.filter(
        migration => !installed.has(migration),
    );

    if (pending.length === 0) {
        console.log(
            `All ${migrations.length} migration(s) already installed; nothing to do.`,
        );
        return;
    }

    // Versions must sort after every migration the project already has, or `supabase db push`
    // treats the copies as inserted before the last applied migration and refuses them without
    // --include-all. Start at the current UTC second, or one second past the newest existing
    // version if that is later -- a project can hold a migration dated ahead of this clock --
    // and give each copy its own second so they keep their original relative order.
    const latest = existing
        .map(file => /^(\d{14})_/.exec(file)?.[1])
        .filter((version): version is string => version !== undefined)
        .sort()
        .at(-1);

    const latestDate = latest === undefined ? undefined : parseVersion(latest);

    const start = Math.max(
        Math.floor(Date.now() / 1000) * 1000,
        latestDate === undefined ? 0 : latestDate.getTime() + 1000,
    );

    for (const [index, migration] of pending.entries()) {
        const source = path.join(sourceDir, migration);

        const version = formatVersion(new Date(start + index * 1000));

        const targetName =
            `${version}${marker}${migration}`;

        const target = path.join(
            targetDir,
            targetName,
        );

        await copyFile(source, target);

        console.log(`Installed ${targetName}`);
    }

    const skipped = migrations.length - pending.length;

    if (skipped > 0) {
        console.log(
            `Skipped ${skipped} migration(s) already present.`,
        );
    }
}

main().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
