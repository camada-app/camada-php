<?php

declare(strict_types=1);

namespace Camada\Challenge;

/**
 * The challenge kit over ext/hash's HMAC-SHA256 and SHA-256, ported from @camada/core
 * src/challenge/verify.ts. Synchronous, so the engine's handle() stays a plain function.
 */
final class Kit
{
    public function __construct(private readonly string $secret)
    {
    }

    private function hmac(string $msg): string
    {
        return hash_hmac('sha256', $msg, $this->secret);
    }

    private function at(string $ip, int $day): string
    {
        return substr($this->hmac(Format::nonceMessage($ip, $day)), 0, Format::NONCE_HEX);
    }

    /** Stateless per-(ip, UTC day) nonce; the verify endpoint recomputes it, nothing is stored. */
    public function nonce(string $ip, int $nowMs): string
    {
        return $this->at($ip, Format::utcDay($nowMs));
    }

    /**
     * Yesterday still passes: a solve started before midnight UTC must not be thrown away.
     * So one solved (nonce, solution) pair is replayable from its own IP for up to ~48 h,
     * minting a fresh 1 h cookie each time. That is the price of a stateless nonce (§D2) and
     * it is deliberate — do not "fix" it into something that needs shared server state.
     */
    public function nonceValid(?string $ip, int $nowMs, ?string $nonce): bool
    {
        if ($ip === null || $ip === '' || $nonce === null || strlen($nonce) !== Format::NONCE_HEX) {
            return false;
        }
        $day = Format::utcDay($nowMs);
        return Format::safeEqual($nonce, $this->at($ip, $day)) || Format::safeEqual($nonce, $this->at($ip, $day - 1));
    }

    public function issue(string $ip, int $nowMs): string
    {
        $exp = $nowMs + Format::CHALLENGE_TTL_MS;
        return $exp . '.' . $this->hmac(Format::tokenMessage($ip, $exp));
    }

    /**
     * A null ip is refused outright: without one the token is bound to nothing, so a single
     * solve would mint a cookie every other unidentified client could present. Adapters must
     * fail open (serve no challenge) rather than challenge a client they cannot identify.
     */
    public function tokenValid(?string $ip, int $nowMs, ?string $cookieValue): bool
    {
        if ($ip === null || $ip === '') {
            return false;
        }
        $t = Format::splitToken($cookieValue);
        if ($t === null) {
            return false;
        }
        [$exp, $mac] = $t;
        if ($exp <= $nowMs || $exp > $nowMs + Format::CHALLENGE_TTL_MS) {
            return false;
        }
        return Format::safeEqual($mac, $this->hmac(Format::tokenMessage($ip, $exp)));
    }

    /** Proof of work ONLY. Never call it without a passing nonceValid() for the same nonce. */
    public function solutionOk(string $nonce, ?string $solution): bool
    {
        return Format::solutionShapeOk($solution) && Format::powOk(hash('sha256', "{$nonce}.{$solution}"));
    }

    /** The whole submission: the nonce is ours and unexpired, and the work is done. */
    public function verify(?string $ip, int $nowMs, ?string $nonce, ?string $solution): bool
    {
        return $this->nonceValid($ip, $nowMs, $nonce) && $this->solutionOk($nonce ?? '', $solution);
    }
}
