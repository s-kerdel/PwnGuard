<?php declare(strict_types=1);

/**
 * DEMO FILE - Fixed version of vulnerable.php
 * This is the answer key for the workshop exercise.
 */

namespace Demo\Fixed;

class UserService
{
    // FIX 1: json_decode instead of unserialize
    public function loadSession(string $data): array
    {
        $decoded = json_decode($data, true);
        if (!is_array($decoded)) {
            throw new \InvalidArgumentException('Invalid session data');
        }
        return $decoded;
    }

    // FIX 2: Parameterized query
    public function findUser(string $email): array
    {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE email = :email');
        $stmt->execute(['email' => $email]);
        return $stmt->fetchAll();
    }

    // FIX 3: URL validation with scheme allowlist and private IP blocking
    private const ALLOWED_DOMAINS = [
        'api.trusted-partner.com',
        'webhooks.example.com',
    ];

    public function fetchWebhook(string $url): string
    {
        $parsed = parse_url($url);

        // Enforce HTTPS only
        if (($parsed['scheme'] ?? '') !== 'https') {
            throw new \InvalidArgumentException('Only HTTPS URLs are allowed');
        }

        // Domain allowlist
        $host = $parsed['host'] ?? '';
        if (!in_array($host, self::ALLOWED_DOMAINS, true)) {
            throw new \InvalidArgumentException('Domain not in allowlist');
        }

        // Block private/reserved IP ranges (DNS rebinding protection)
        $ip = gethostbyname($host);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            throw new \InvalidArgumentException('Resolved to internal IP range');
        }

        return file_get_contents($url);
    }

    // FIX 4: Allowlist approach instead of OR-logic denylist
    private const ALLOWED_ROUTES = [
        'public.home',
        'public.login',
        'public.register',
    ];

    public function isAllowed(string $route): bool
    {
        return in_array($route, self::ALLOWED_ROUTES, true);
    }
}

// FIX 5: Use {{ textInterpolation }} instead of v-html
// In .twig: <span>{{ userInput }}</span>
// If HTML rendering is needed: sanitize with DOMPurify first
