<?php

require_once __DIR__ . '/rememberme_crypto.php';

/**
 * rememberme
 *
 * Adds a "Keep me logged in" checkbox to the Roundcube login page. Ticking
 * it remembers that browser for a set number of days:
 *
 *  - only that browser's sessions get a longer inactivity timeout -- the
 *    global session_lifetime is untouched for everyone else, and for the
 *    same user on any browser where they didn't tick the box;
 *  - if the session is cleared anyway (expired, garbage-collected, server
 *    restart), the next page load logs the browser straight back in from
 *    its cookie;
 *  - logging out, revoking the device under Settings -> Remembered
 *    devices, or changing the password (password plugin) ends it.
 *
 * See rememberme_crypto for how the token and stored password are
 * protected.
 *
 * @author Gavin Taylor
 *
 * Copyright (C) Gavin Taylor
 *
 * This program is a Roundcube (https://roundcube.net) plugin.
 * For more information see README.md.
 * For configuration see config.inc.php.dist.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see https://www.gnu.org/licenses/.
 */
class rememberme extends rcube_plugin
{
    private const TABLE = 'rememberme_tokens';
    private const VERSION_KEY = 'rememberme-schema-version';
    private const SCHEMA_VERSION = '2026101401';

    private $rc;

    /** The validated token row for this request's cookie, if any. */
    private $current;

    /** The validator from this request's cookie (needed to decrypt). */
    private $validator;

    /** Credentials for a cookie-driven automatic login in progress. */
    private $auto;

    /** Password captured from a manual login with the box ticked. */
    private $remember_password;

    private $schema_checked = false;

    #[\Override]
    public function init()
    {
        $this->rc = rcmail::get_instance();
        $this->load_config('config.inc.php.dist');
        $this->load_config();
        $this->add_texts('localization/', true);

        // A valid remember-me cookie extends *this* browser's session
        // lifetime: the session row's expires_at and the auth cookie's time
        // window both use it, so it has to be in place before core checks
        // the session and writes it back.
        if ($this->rc->task !== 'logout' && $this->load_cookie_token()) {
            $this->extend_session_lifetime();
        }

        $this->add_hook('startup', [$this, 'startup']);
        $this->add_hook('authenticate', [$this, 'authenticate']);
        $this->add_hook('login_after', [$this, 'login_after']);
        $this->add_hook('login_failed', [$this, 'login_failed']);
        $this->add_hook('logout_after', [$this, 'logout_after']);
        $this->add_hook('template_object_loginform', [$this, 'login_form']);
        $this->add_hook('password_change', [$this, 'password_change']);
        $this->add_hook('settings_actions', [$this, 'settings_actions']);

        $this->register_action('plugin.rememberme', [$this, 'settings_page']);
        $this->register_action('plugin.rememberme.revoke', [$this, 'revoke']);

        if ($this->rc->task === 'login' || $this->rc->task === 'settings') {
            $this->include_stylesheet($this->local_skin_path() . '/rememberme.css');
        }
    }

    // ---------------------------------------------------------------------
    // Configuration
    // ---------------------------------------------------------------------

    private function days(): int
    {
        return max(1, (int) $this->rc->config->get('rememberme_days', 30));
    }

    private function cookie_name(): string
    {
        return (string) $this->rc->config->get('rememberme_cookie', 'roundcube_rememberme');
    }

    private function user_allowed(string $username): bool
    {
        $users = $this->rc->config->get('rememberme_users');

        return empty($users) || in_array($username, (array) $users, true);
    }

    /**
     * Only ever offered or honoured over HTTPS -- the cookie is a bearer
     * credential.
     */
    private function enabled(): bool
    {
        return rcube_utils::https_check();
    }

    private function extend_session_lifetime(): void
    {
        $minutes = $this->days() * 1440;
        $this->rc->config->set('session_lifetime', $minutes);

        // Roundcube 1.7 runs plugin init() after the session has started
        // (but before it's written back), so update the live session too --
        // its expires_at is written with this lifetime at the end of the
        // request. And the page's own copy, used for keep-alive timing.
        if ($this->rc->session) {
            $this->rc->session->set_lifetime($minutes * 60);
        }
        if ($this->rc->output) {
            $this->rc->output->set_env('session_lifetime', $minutes * 60);
        }
    }

    // ---------------------------------------------------------------------
    // Cookie
    // ---------------------------------------------------------------------

    private function set_cookie(string $value): void
    {
        rcube_utils::setcookie($this->cookie_name(), $value, time() + $this->days() * 86400, true);
    }

    private function clear_cookie(): void
    {
        rcube_utils::setcookie($this->cookie_name(), '', time() - 3600, true);
        unset($_COOKIE[$this->cookie_name()]);
    }

    /**
     * Validates this request's cookie against the database. On success
     * sets $this->current / $this->validator; a cookie that doesn't check
     * out is cleared so the browser stops sending it.
     */
    private function load_cookie_token(): bool
    {
        $raw = $_COOKIE[$this->cookie_name()] ?? null;

        if ($raw === null || !$this->enabled()) {
            return false;
        }

        $parts = rememberme_crypto::parse_cookie($raw);
        $row = $parts ? $this->find_by_selector($parts['selector']) : null;

        if (!$row || !rememberme_crypto::validator_matches($parts['validator'], $row['validator_hash'])
            || strtotime($row['expires']) <= time() || !$this->user_allowed($row['username'])
        ) {
            if ($row && $parts && !rememberme_crypto::validator_matches($parts['validator'], $row['validator_hash'])) {
                // Right selector, wrong secret: someone has a forged or
                // stale copy. Drop the token rather than leave it guessable.
                $this->delete_token((int) $row['id']);
                $this->log('rejected token with bad validator', $row['username']);
            }
            $this->clear_cookie();

            return false;
        }

        $this->current = $row;
        $this->validator = $parts['validator'];

        return true;
    }

    // ---------------------------------------------------------------------
    // Login / logout hooks
    // ---------------------------------------------------------------------

    /**
     * A remembered browser with no live session: turn this page load into
     * a login, so core's normal login flow runs (session id regeneration,
     * auth cookie, login logging, login_after hooks).
     */
    public function startup($args)
    {
        if (!$this->current || !empty($_SESSION['user_id'])
            || $args['task'] === 'logout' || ($args['task'] === 'login' && $args['action'] === 'login')
            || ($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET'
            || !empty($_REQUEST['_remote']) || !empty($_SERVER['HTTP_X_ROUNDCUBE_REQUEST'])
        ) {
            return $args;
        }

        $password = rememberme_crypto::decrypt($this->current['secret'], $this->validator,
            (string) $this->rc->config->get('des_key'));

        if ($password === null) {
            $this->delete_token((int) $this->current['id']);
            $this->clear_cookie();
            $this->log('could not decrypt stored password; token removed', $this->current['username']);

            return $args;
        }

        $this->auto = [
            'user' => $this->current['username'],
            'pass' => $password,
            'host' => $this->current['host'],
        ];

        // Come back to the page that was asked for, as a manual login does.
        $query = $_GET;
        unset($query['_err'], $query['_task'], $query['_action']);
        if (!empty($_GET['_task']) && $_GET['_task'] !== 'login') {
            $query = ['_task' => $_GET['_task']] + (empty($_GET['_action']) ? [] : ['_action' => $_GET['_action']]) + $query;
        }
        $_POST['_url'] = http_build_query($query);

        return ['task' => 'login', 'action' => 'login'] + $args;
    }

    public function authenticate($args)
    {
        if ($this->auto) {
            return array_merge($args, $this->auto, ['valid' => true, 'cookiecheck' => false]);
        }

        if ($this->enabled() && rcube_utils::get_input_string('_rememberme', rcube_utils::INPUT_POST) === '1'
            && $this->user_allowed((string) $args['user'])
        ) {
            $this->remember_password = $args['pass'];
            // Before core sets the session's auth cookie, whose time window
            // depends on the lifetime -- otherwise the very next request
            // (now carrying the remember-me cookie, so the long lifetime)
            // would fail the auth check once.
            $this->extend_session_lifetime();
        }

        return $args;
    }

    public function login_after($args)
    {
        $db = $this->rc->get_dbh();

        if ($this->auto) {
            $id = (int) $this->current['id'];
            $db->query('UPDATE ' . $this->table() . ' SET last_used = ' . $db->now() . ', ip = ?, user_agent = ? WHERE id = ?',
                rcube_utils::remote_addr(), $this->user_agent(), $id);
            $_SESSION['rememberme_id'] = $id;
            $this->log('automatic login', $this->current['username']);
        } elseif ($this->remember_password !== null) {
            $this->create_token($this->remember_password);
        }

        $this->remember_password = null;

        return $args;
    }

    /**
     * A stored password that no longer works (changed elsewhere): forget
     * the device, and the normal login page follows.
     */
    public function login_failed($args)
    {
        if ($this->auto) {
            $this->delete_token((int) $this->current['id']);
            $this->clear_cookie();
            $this->log('automatic login failed; token removed', $this->current['username']);
            $this->auto = null;
        }

        return $args;
    }

    /**
     * Logging out means "forget this device" -- otherwise the cookie would
     * just log the browser straight back in.
     */
    public function logout_after($args)
    {
        $parts = rememberme_crypto::parse_cookie($_COOKIE[$this->cookie_name()] ?? null);

        if ($parts && ($row = $this->find_by_selector($parts['selector']))) {
            $this->delete_token((int) $row['id']);
        }

        $this->clear_cookie();

        return $args;
    }

    /**
     * Password changed through the password plugin: every remembered
     * device holds the old password, so forget them all.
     */
    public function password_change($args)
    {
        if (!empty($this->rc->user->ID)) {
            $this->ensure_schema();
            $this->rc->get_dbh()->query('DELETE FROM ' . $this->table() . ' WHERE user_id = ?', $this->rc->user->ID);
            $this->clear_cookie();
            unset($_SESSION['rememberme_id']);
        }

        return $args;
    }

    public function login_form($args)
    {
        if (!$this->enabled()) {
            return $args;
        }

        // Keep the box ticked when the form comes back after a failed login.
        $ticked = rcube_utils::get_input_string('_rememberme', rcube_utils::INPUT_POST) === '1';
        $checkbox = new html_checkbox(['name' => '_rememberme', 'id' => 'rcmloginrememberme', 'value' => '1']);
        $row = html::div('rememberme-option',
            html::label('rcmloginrememberme', $checkbox->show($ticked ? '1' : '') . ' ' . rcube::Q($this->gettext('keepmeloggedin'))));

        // After the username/password table, so Elastic's login-form
        // restyling (which turns each table row into an icon input group)
        // leaves it alone.
        $args['content'] = str_contains($args['content'], '</table>')
            ? preg_replace('~</table>~', '</table>' . $row, $args['content'], 1)
            : $args['content'] . $row;

        return $args;
    }

    // ---------------------------------------------------------------------
    // Settings -> Remembered devices
    // ---------------------------------------------------------------------

    public function settings_actions($args)
    {
        $args['actions'][] = [
            'action' => 'plugin.rememberme',
            'class' => 'rememberme',
            'label' => 'rememberme.devices',
            'title' => 'rememberme.devices',
            'domain' => 'rememberme',
        ];

        return $args;
    }

    public function settings_page()
    {
        $this->rc->output->set_pagetitle($this->gettext('devices'));
        $this->include_script('rememberme.js');
        $this->register_handler('plugin.body', [$this, 'render_devices']);
        $this->rc->output->send('plugin');
    }

    public function render_devices()
    {
        $this->ensure_schema();
        $db = $this->rc->get_dbh();
        $result = $db->query('SELECT * FROM ' . $this->table() . ' WHERE user_id = ? AND expires > ' . $db->now() . ' ORDER BY last_used DESC',
            $this->rc->user->ID);
        $current = (int) ($_SESSION['rememberme_id'] ?? 0);

        $table = new html_table(['class' => 'records-table rememberme-devices', 'cols' => 6]);
        // Columns marked rememberme-wide drop out on narrow screens (see
        // rememberme.css), so the list still fits a phone.
        foreach (['device' => '', 'firstsignedin' => 'rememberme-wide', 'lastused' => '',
            'expires' => 'rememberme-wide', 'ipaddress' => 'rememberme-wide', '' => ''] as $col => $class) {
            $table->add_header($class ?: null, $col === '' ? '' : rcube::Q($this->gettext($col)));
        }

        $count = 0;
        while ($row = $db->fetch_assoc($result)) {
            $count++;
            $id = (int) $row['id'];
            $table->add_row(['id' => 'rememberme-row-' . $id]);
            $table->add(null, rcube::Q($this->describe_agent($row['user_agent']))
                . ($id === $current ? ' ' . html::span('rememberme-current', rcube::Q($this->gettext('thisdevice'))) : ''));
            $table->add('rememberme-wide', rcube::Q($this->rc->format_date($row['created'])));
            $table->add(null, rcube::Q($this->rc->format_date($row['last_used'])));
            $table->add('rememberme-wide', rcube::Q($this->rc->format_date($row['expires'])));
            $table->add('rememberme-wide', rcube::Q($row['ip']));
            $table->add(null, html::tag('button', ['type' => 'button', 'class' => 'button rememberme-revoke',
                'data-id' => $id, 'data-current' => $id === $current ? '1' : '0'], rcube::Q($this->gettext('signout'))));
        }

        $intro = html::p(null, rcube::Q($this->gettext(['name' => 'devicesintro', 'vars' => ['days' => $this->days()]])));

        $body = $count
            // Not Elastic's 'formbuttons': on small screens it copies those
            // buttons into its footer bar, duplicating this one.
            ? $table->show() . html::p('rememberme-actions', html::tag('button', ['type' => 'button',
                'class' => 'button rememberme-revoke-others', 'id' => 'rememberme-revoke-others'],
                rcube::Q($this->gettext('signoutothers'))))
            : html::p('hint', rcube::Q($this->gettext('nodevices')));

        return html::div(['class' => 'rememberme-settings'], $intro . $body);
    }

    /**
     * AJAX: forget one device (_id) or every device but this one
     * (_others=1). Scoped to the logged-in user's own tokens.
     */
    public function revoke()
    {
        $this->ensure_schema();
        $db = $this->rc->get_dbh();
        $current = (int) ($_SESSION['rememberme_id'] ?? 0);

        if (rcube_utils::get_input_string('_others', rcube_utils::INPUT_POST) === '1') {
            $db->query('DELETE FROM ' . $this->table() . ' WHERE user_id = ? AND id <> ?', $this->rc->user->ID, $current);
            $this->rc->output->show_message($this->gettext('signedoutothers'), 'confirmation');
        } else {
            $id = (int) rcube_utils::get_input_string('_id', rcube_utils::INPUT_POST);
            $db->query('DELETE FROM ' . $this->table() . ' WHERE user_id = ? AND id = ?', $this->rc->user->ID, $id);

            if ($id === $current) {
                // This browser: stop it logging itself back in. The current
                // session carries on until it ends normally.
                $this->clear_cookie();
                unset($_SESSION['rememberme_id']);
            }
            $this->rc->output->show_message($this->gettext('signedout'), 'confirmation');
        }

        $this->rc->output->command('plugin.rememberme_reload');
        $this->rc->output->send();
    }

    // ---------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------

    private function table(): string
    {
        return $this->rc->get_dbh()->table_name(self::TABLE, true);
    }

    private function create_token(string $password): void
    {
        $this->ensure_schema();
        $db = $this->rc->get_dbh();
        $token = rememberme_crypto::new_token();
        $user_id = (int) $this->rc->user->ID;

        // Tidy up: expired tokens, and keep at most rememberme_max_devices
        // per user (the oldest go first).
        $db->query('DELETE FROM ' . $this->table() . ' WHERE expires <= ' . $db->now());
        $max = max(1, (int) $this->rc->config->get('rememberme_max_devices', 10));
        $result = $db->query('SELECT id FROM ' . $this->table() . ' WHERE user_id = ? ORDER BY last_used DESC', $user_id);
        $keep = 0;
        while ($row = $db->fetch_assoc($result)) {
            if (++$keep >= $max) {
                $this->delete_token((int) $row['id']);
            }
        }

        $db->query(
            'INSERT INTO ' . $this->table() . ' (user_id, selector, validator_hash, secret, username, host, created, last_used, expires, user_agent, ip)'
            . ' VALUES (?, ?, ?, ?, ?, ?, ' . $db->now() . ', ' . $db->now() . ', ' . $db->now($this->days() * 86400) . ', ?, ?)',
            $user_id,
            $token['selector'],
            rememberme_crypto::hash_validator($token['validator']),
            rememberme_crypto::encrypt($password, $token['validator'], (string) $this->rc->config->get('des_key')),
            (string) $_SESSION['username'],
            (string) $_SESSION['storage_host'],
            $this->user_agent(),
            rcube_utils::remote_addr()
        );

        $_SESSION['rememberme_id'] = (int) $db->insert_id(self::TABLE);
        $this->set_cookie(rememberme_crypto::cookie_value($token['selector'], $token['validator']));
        $this->log('device remembered', (string) $_SESSION['username']);
    }

    private function find_by_selector(string $selector): ?array
    {
        $this->ensure_schema();
        $db = $this->rc->get_dbh();
        $row = $db->fetch_assoc($db->query('SELECT * FROM ' . $this->table() . ' WHERE selector = ?', $selector));

        return $row ?: null;
    }

    private function delete_token(int $id): void
    {
        $this->ensure_schema();
        $this->rc->get_dbh()->query('DELETE FROM ' . $this->table() . ' WHERE id = ?', $id);
    }

    /**
     * Creates the table on first use (same approach as this author's
     * markasphishing plugin), tracking the schema version in Roundcube's
     * own `system` table. MySQL/MariaDB only for now.
     */
    private function ensure_schema(): void
    {
        if ($this->schema_checked) {
            return;
        }

        $db = $this->rc->get_dbh();
        $system = $db->table_name('system', true);
        $row = $db->fetch_assoc($db->query("SELECT value FROM {$system} WHERE name = ?", self::VERSION_KEY));

        if (!$row) {
            $sql = preg_replace('/^--.*$/m', '', file_get_contents($this->home . '/SQL/mysql.initial.sql'));
            foreach (array_filter(array_map('trim', explode(';', $sql))) as $statement) {
                $db->query($statement);
            }
            $db->query("INSERT INTO {$system} (name, value) VALUES (?, ?)", self::VERSION_KEY, self::SCHEMA_VERSION);
        }

        $this->schema_checked = true;
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private function user_agent(): string
    {
        return substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255);
    }

    /**
     * A short "Firefox on Linux" style label for the devices list.
     */
    private function describe_agent(string $ua): string
    {
        $browser = match (true) {
            str_contains($ua, 'Edg/') => 'Edge',
            str_contains($ua, 'Firefox/') => 'Firefox',
            str_contains($ua, 'Chrome/') => 'Chrome',
            str_contains($ua, 'Safari/') => 'Safari',
            default => $this->gettext('unknownbrowser'),
        };
        $os = match (true) {
            str_contains($ua, 'Android') => 'Android',
            str_contains($ua, 'iPhone') || str_contains($ua, 'iPad') => 'iOS',
            str_contains($ua, 'Windows') => 'Windows',
            str_contains($ua, 'Mac OS X') => 'macOS',
            str_contains($ua, 'Linux') => 'Linux',
            default => '',
        };

        return $os ? $this->gettext(['name' => 'browseron', 'vars' => ['browser' => $browser, 'os' => $os]]) : $browser;
    }

    private function log(string $message, string $user): void
    {
        if ($this->rc->config->get('rememberme_log', true)) {
            rcube::write_log('rememberme', sprintf('user=%s ip=%s %s', $user, rcube_utils::remote_addr(), $message));
        }
    }
}
