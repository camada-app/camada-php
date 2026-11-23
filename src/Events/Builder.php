<?php

declare(strict_types=1);

namespace Camada\Events;

use Camada\Redact;
use Camada\Req;

/**
 * Wire-event builder: reproduces the collector's record() (edge-analyst
 * workers/collector/edge-collector.js) from a normalized request, so events are comparable
 * across taps. HDRS bit order is pinned by the shared fixture (hdrs.json) — never reorder.
 */
final class Builder
{
    public const HDRS = [
        'accept', 'accept-language', 'accept-encoding', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest',
        'sec-fetch-user', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'upgrade-insecure-requests', 'dnt',
        'cache-control', 'pragma', 'referer', 'origin', 'cookie', 'authorization', 'x-requested-with', 'content-type',
        'via', 'x-forwarded-for', 'priority', 'sec-purpose', 'save-data', 'te', 'if-modified-since', 'if-none-match',
    ];

    public static function authScheme(?string $value): ?string
    {
        return Redact::authScheme($value);
    }

    /** @return 'urlencoded'|'multipart'|null */
    public static function formType(?string $contentType): ?string
    {
        $mediaType = trim(explode(';', $contentType ?? '', 2)[0], " \t");
        return match (Redact::asciiLower($mediaType)) {
            'application/x-www-form-urlencoded' => 'urlencoded',
            'multipart/form-data' => 'multipart',
            default => null,
        };
    }

    public static function nowMs(): int
    {
        return (int) floor(microtime(true) * 1000);
    }

    /**
     * The mutable wire event; the caller fills st/dur on response-finish before spooling it.
     *
     * @return array<string, mixed>
     */
    public static function wireEvent(
        Req $r,
        ?string $ip,
        string $tap,
        string $rid,
        ?string $sid = null,
        bool $newSession = false,
        ?string $ja4 = null,
        ?RowOptions $options = null,
    ): array {
        static $bits = null;
        if ($bits === null) {
            $bits = [];
            foreach (self::HDRS as $i => $name) {
                $bits[$name] = 1 << $i;
            }
        }
        $mask = $hn = $hb = 0;
        $cookie = '';
        $names = [];
        /** @var array<string, string> $first */
        $first = [];
        foreach ($r->headers as [$name, $value]) {
            $k = strtolower($name);
            $hn++;
            $hb += strlen($name) + strlen($value);
            $names[] = $k;
            if (!isset($first[$k])) {
                $first[$k] = $value;
            }
            $mask |= $bits[$k] ?? 0;
            if ($k === 'cookie') {
                $cookie = $cookie !== '' ? $cookie . '; ' . $value : $value;
            }
        }
        $h = static fn (string $k): ?string => $first[$k] ?? null;
        $query = $r->query;
        $qn = strlen($query) > 1 ? count(array_filter(explode('&', substr($query, 1)), static fn (string $p): bool => $p !== '')) : 0;
        $ev = [
            'tap' => $tap, 'rid' => $rid, 'sid' => $sid, 'ns' => $newSession ? 1 : 0, 'ts' => self::nowMs(),
            'ip' => $ip,
            'proto' => $r->httpVersion !== null && $r->httpVersion !== '' ? "HTTP/{$r->httpVersion}" : null,
            'm' => $r->method, 'h' => $r->host, 'p' => $r->path, 'q' => substr(Redact::scrubQuery($query), 0, 512), 'qn' => $qn,
            'ct' => $h('content-type'), 'cl' => $h('content-length'),
            'ua' => $h('user-agent'), 'chua' => $h('sec-ch-ua'), 'chmob' => $h('sec-ch-ua-mobile'), 'chplat' => $h('sec-ch-ua-platform'),
            'acc' => $h('accept'), 'lang' => $h('accept-language'), 'fs' => $h('sec-fetch-site'), 'fm' => $h('sec-fetch-mode'),
            'fd' => $h('sec-fetch-dest'), 'fu' => $h('sec-fetch-user'), 'ref' => Redact::scrubUrl($h('referer')), 'org' => $h('origin'),   // ref: the previous page's query is scrubbed too
            'xrw' => $h('x-requested-with'), 'auth' => self::authScheme($h('authorization')),   // scheme only, never the credential
            'hm' => $mask, 'hn' => $hn, 'hb' => $hb, 'ck' => $cookie !== '' ? count(explode(';', $cookie)) : 0,
            'hord' => substr(implode(',', $names), 0, 2048),   // header order as this host reports it (a hash under FastCGI)
        ];
        if ($ja4 !== null && $ja4 !== '') {
            $ev['ja4'] = $ja4;
        }
        if (($tokenHasher = $options?->tokenHasher) !== null) {
            try {
                $credential = Redact::selectCredential($first, $options->tokenHeader);
                if ($credential !== null) {
                    $tk = $tokenHasher($credential);
                    if ($tk !== null && $tk !== '') {
                        $ev['tk'] = $tk;
                    }
                }
            } catch (\Throwable) {
                // A hashing failure must leave enforcement intact and may contain the credential.
            }
        }
        try {
            if (($r->post !== [] || $r->files !== []) && ($form = self::formType($h('content-type'))) !== null) {
                $progressName = $options->progressName ?? false;
                if ($form === 'multipart' && $progressName !== false && $progressName !== '' && array_key_exists($progressName, $r->post)) {
                    $ev['upf'] = 1;
                }
                $fields = Redact::fieldNames($r->post, $r->files);
                if ($fields !== null) {
                    $ev['bf'] = $fields;
                }
            }
        } catch (\Throwable) {
            // Optional form metadata must not interrupt enforcement.
        }
        $ev['st'] = null;
        $ev['dur'] = null;   // 'dur': the collector wire already claims 'lat' for latitude
        return $ev;
    }
}
