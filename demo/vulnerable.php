<?php declare(strict_types=1);

/**
 * DEMO FILE - Intentionally vulnerable code for security audit testing.
 * DO NOT use in production. Used to verify the audit tool catches issues.
 *
 * Expected findings:
 *   1. CRITICAL - unserialize() without allowed_classes (CWE-502)
 *   2. HIGH     - SQL injection via string interpolation (CWE-89)
 *   3. HIGH     - SSRF via unvalidated URL (CWE-918)
 *   4. MEDIUM   - OR-logic authorization bypass (CWE-863)
 *   5. MEDIUM   - XSS via v-html in template (CWE-79)
 *   6. LOW      - FILTER_VALIDATE_URL used as security check
 *
 * Run: python audit.py --mode manual --files demo/vulnerable.php
 */

namespace Demo\Vulnerable;

class UserService
{
    // BUG 1: Insecure deserialization
    public function loadSession(string $data): object
    {
        return unserialize($data);
    }

    // BUG 2: SQL injection
    public function findUser(string $email): array
    {
        $sql = "SELECT * FROM users WHERE email = '" . $email . "'";
        return $this->db->fetchAll($sql);
    }

    // BUG 3: SSRF - no URL validation
    public function fetchWebhook(string $url): string
    {
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new \InvalidArgumentException('Invalid URL');
        }
        // BUG 6: FILTER_VALIDATE_URL passes http://127.0.0.1
        return file_get_contents($url);
    }

    // BUG 4: OR-logic authorization bypass
    public function isAllowed(string $route): bool
    {
        return $route === 'public.home'
            || !str_starts_with($route, 'admin')
            || !str_ends_with($route, 'page');
    }
}

// BUG 5: Template with v-html XSS sink
// In a .twig file this would be:
// <span v-html="userInput"></span>
