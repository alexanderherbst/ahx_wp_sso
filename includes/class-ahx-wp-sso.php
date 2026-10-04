<?php

if (!defined('ABSPATH')) {
    exit;
}

final class AHX_WP_SSO {
    const ACTION = 'ahx_wp_sso';
    const REST_NAMESPACE = 'ahx-wp-sso/v1';
    const DB_SCHEMA_VERSION = '2';
    const FLOW_LIFETIME = 300;
    const SESSION_CACHE_LIFETIME = 15;
    const HOST_CHECK_CACHE_LIFETIME = 5;

    private static $instance;
    private $host_availability;

    public static function instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public static function activate($network_wide) {
        self::install_tables();
        update_site_option('ahx_wp_sso_db_schema_version', self::DB_SCHEMA_VERSION);
    }

    private static function install_tables() {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();
        $prefix = $wpdb->base_prefix;
        $clients = $prefix . 'ahx_wp_sso_clients';
        $codes = $prefix . 'ahx_wp_sso_codes';
        $sessions = $prefix . 'ahx_wp_sso_host_sessions';
        $client_sessions = $prefix . 'ahx_wp_sso_client_sessions';
        $client_activity = $prefix . 'ahx_wp_sso_client_activity';

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta("CREATE TABLE $clients (
            client_id char(64) NOT NULL,
            secret_hash char(64) NOT NULL,
            client_name varchar(190) NOT NULL,
            redirect_uri text NOT NULL,
            created_at datetime NOT NULL,
            PRIMARY KEY  (client_id)
        ) $charset;");
        dbDelta("CREATE TABLE $codes (
            code_hash char(64) NOT NULL,
            client_id char(64) NOT NULL,
            user_id bigint(20) unsigned NOT NULL,
            host_session_id char(64) NOT NULL DEFAULT '',
            code_challenge char(64) NOT NULL,
            expires_at datetime NOT NULL,
            used_at datetime NULL DEFAULT NULL,
            PRIMARY KEY  (code_hash),
            KEY expires_at (expires_at),
            KEY client_id (client_id)
        ) $charset;");
        dbDelta("CREATE TABLE $sessions (
            session_id char(64) NOT NULL,
            user_id bigint(20) unsigned NOT NULL,
            host_token_hash char(64) NOT NULL,
            active tinyint(1) NOT NULL DEFAULT 1,
            created_at datetime NOT NULL,
            revoked_at datetime NULL DEFAULT NULL,
            PRIMARY KEY  (session_id),
            KEY user_active (user_id,active),
            UNIQUE KEY host_token_hash (host_token_hash)
        ) $charset;");
        dbDelta("CREATE TABLE $client_sessions (
            token_hash char(64) NOT NULL,
            user_id bigint(20) unsigned NOT NULL,
            session_id char(64) NOT NULL,
            client_session_id char(64) NOT NULL DEFAULT '',
            created_at datetime NOT NULL,
            PRIMARY KEY  (token_hash),
            KEY session_id (session_id),
            KEY user_id (user_id)
        ) $charset;");
        dbDelta("CREATE TABLE $client_activity (
            client_session_id char(64) NOT NULL,
            client_id char(64) NOT NULL,
            session_id char(64) NOT NULL,
            user_id bigint(20) unsigned NOT NULL,
            active tinyint(1) NOT NULL DEFAULT 1,
            created_at datetime NOT NULL,
            last_seen_at datetime NOT NULL,
            expires_at datetime NULL DEFAULT NULL,
            revoked_at datetime NULL DEFAULT NULL,
            PRIMARY KEY  (client_session_id),
            KEY client_active (client_id,active),
            KEY session_active (session_id,active),
            KEY user_id (user_id)
        ) $charset;");
    }

    private function __construct() {
        add_action('plugins_loaded', array($this, 'maybe_upgrade'), 1);
        add_action('admin_menu', array($this, 'add_settings_page'));
        add_action('admin_menu', array($this, 'add_dashboard_page'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_post_ahx_wp_sso_add_client', array($this, 'add_client'));
        add_action('admin_post_ahx_wp_sso_save_client_branding', array($this, 'save_client_branding'));
        add_action('admin_post_ahx_wp_sso_remove_client', array($this, 'remove_client'));
        add_action('admin_notices', array($this, 'show_setup_notice'));
        add_action('rest_api_init', array($this, 'register_rest_routes'));
        add_action('login_init', array($this, 'handle_login'), 1);
        add_action('admin_bar_menu', array($this, 'add_logout_menu'), 100);
        add_action('init', array($this, 'validate_client_session'), 2);
        add_action('set_auth_cookie', array($this, 'record_break_glass_cookie'), 10, 6);
        add_filter('authenticate', array($this, 'block_local_client_login'), 99, 3);
        add_filter('login_message', array($this, 'break_glass_login_message'));
        add_filter('login_message', array($this, 'client_login_message'), 20);
        add_filter('login_title', array($this, 'client_login_title'), 10, 3);
        add_filter('login_headerurl', array($this, 'client_login_header_url'));
        add_filter('login_headertext', array($this, 'client_login_header_text'));
        add_action('login_head', array($this, 'client_login_styles'));
    }

    public function maybe_upgrade() {
        if (self::DB_SCHEMA_VERSION !== get_site_option('ahx_wp_sso_db_schema_version')) {
            self::install_tables();
            update_site_option('ahx_wp_sso_db_schema_version', self::DB_SCHEMA_VERSION);
        }
    }

    public function add_settings_page() {
        add_options_page(
            __('AHX WP SSO Einstellungen', 'ahx-wp-sso'),
            'AHX WP SSO',
            'manage_options',
            'ahx-wp-sso',
            array($this, 'render_settings_page')
        );
    }

    public function add_dashboard_page() {
        if ('host' !== $this->config()['mode']) {
            return;
        }
        add_menu_page(
            __('AHX WP SSO Dashboard', 'ahx-wp-sso'),
            __('AHX SSO Dashboard', 'ahx-wp-sso'),
            'manage_options',
            'ahx-wp-sso-dashboard',
            array($this, 'render_dashboard'),
            'dashicons-admin-site-alt3',
            3
        );
    }

    public function render_dashboard() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unzureichende Berechtigung.', 'ahx-wp-sso'), '', array('response' => 403));
        }
        if ('host' !== $this->config()['mode']) {
            wp_die(esc_html__('Das Dashboard ist nur auf einer als SSO-Host konfigurierten Site verfuegbar.', 'ahx-wp-sso'), '', array('response' => 400));
        }

        global $wpdb;
        $clients = $wpdb->get_results("SELECT client_id, client_name, redirect_uri, created_at FROM " . $this->table('clients') . " ORDER BY client_name ASC");
        if (!empty($wpdb->last_error)) {
            error_log('AHX WP SSO dashboard could not load clients: ' . $wpdb->last_error);
            $clients = false;
        }
        $activities = $wpdb->get_results(
            "SELECT a.client_session_id, a.client_id, a.session_id, a.user_id, a.created_at, a.last_seen_at, a.expires_at, a.revoked_at, a.active, c.client_name, s.active AS sso_active, s.host_token_hash
            FROM " . $this->table('client_activity') . " a
            LEFT JOIN " . $this->table('clients') . " c ON c.client_id = a.client_id
            LEFT JOIN " . $this->table('host_sessions') . " s ON s.session_id = a.session_id
            ORDER BY a.last_seen_at DESC
            LIMIT 500"
        );
        if (!empty($wpdb->last_error)) {
            error_log('AHX WP SSO dashboard could not load session activity: ' . $wpdb->last_error);
            $activities = false;
        }
        $active_sessions = 0;
        if (is_array($activities)) {
            foreach ($activities as $activity) {
                if ($this->activity_is_active($activity)) {
                    ++$active_sessions;
                }
            }
        }
        $health_url = add_query_arg('rest_route', '/' . self::REST_NAMESPACE . '/health', home_url('/'));
        $token_url = $this->host_rest_url('token');
        $session_url = $this->host_rest_url('session');
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('AHX WP SSO Dashboard', 'ahx-wp-sso'); ?></h1>
            <p><?php esc_html_e('Übersicht der registrierten Client-Sites, aktiven SSO-Sitzungen und Betriebsparameter. Client-Secrets und Sitzungstoken werden nicht angezeigt.', 'ahx-wp-sso'); ?></p>
            <div class="notice notice-info inline"><p><?php esc_html_e('Aktiv bedeutet: Die Client-Site hat die SSO-Sitzung zuletzt bestätigt, die Sitzung ist am Host nicht widerrufen und die zugehörige WordPress-Host-Sitzung ist noch gültig. Der Aktivitätszeitpunkt wird bei der Client-Sitzungsprüfung aktualisiert.', 'ahx-wp-sso'); ?></p></div>

            <div style="display:flex;gap:16px;flex-wrap:wrap;margin:20px 0">
                <div class="card"><h2><?php esc_html_e('Betriebsart', 'ahx-wp-sso'); ?></h2><p><strong><?php esc_html_e('Dedizierter SSO-Host', 'ahx-wp-sso'); ?></strong></p></div>
                <div class="card"><h2><?php esc_html_e('Registrierte Clients', 'ahx-wp-sso'); ?></h2><p><strong><?php echo is_array($clients) ? esc_html(number_format_i18n(count($clients))) : '—'; ?></strong></p></div>
                <div class="card"><h2><?php esc_html_e('Aktive Client-Sitzungen (Liste)', 'ahx-wp-sso'); ?></h2><p><strong><?php echo is_array($activities) ? esc_html(number_format_i18n($active_sessions)) : '—'; ?></strong></p></div>
                <div class="card"><h2><?php esc_html_e('Letzter Seitenaufruf', 'ahx-wp-sso'); ?></h2><p><?php echo esc_html(wp_date(get_option('date_format') . ' ' . get_option('time_format'))); ?></p></div>
            </div>

            <h2><?php esc_html_e('Betriebsparameter', 'ahx-wp-sso'); ?></h2>
            <table class="widefat striped" style="max-width:1000px">
                <tbody>
                    <tr><th><?php esc_html_e('WordPress-Site-URL', 'ahx-wp-sso'); ?></th><td><code><?php echo esc_html(set_url_scheme(site_url('/'), 'https')); ?></code></td></tr>
                    <tr><th><?php esc_html_e('Callback-Muster der Clients', 'ahx-wp-sso'); ?></th><td><code>https://client.example/wp-login.php?ahx_wp_sso=callback</code></td></tr>
                    <tr><th><?php esc_html_e('Health-Endpunkt', 'ahx-wp-sso'); ?></th><td><code><?php echo esc_html($health_url); ?></code></td></tr>
                    <tr><th><?php esc_html_e('Token-Endpunkt', 'ahx-wp-sso'); ?></th><td><code><?php echo esc_html($token_url); ?></code></td></tr>
                    <tr><th><?php esc_html_e('Sitzungs-Endpunkt', 'ahx-wp-sso'); ?></th><td><code><?php echo esc_html($session_url); ?></code></td></tr>
                    <tr><th><?php esc_html_e('TLS für diese Anfrage', 'ahx-wp-sso'); ?></th><td><?php echo is_ssl() ? esc_html__('Aktiv', 'ahx-wp-sso') : esc_html__('Nicht erkannt – SSO erfordert HTTPS', 'ahx-wp-sso'); ?></td></tr>
                    <tr><th><?php esc_html_e('Autorisierungscode gültig für', 'ahx-wp-sso'); ?></th><td><?php echo esc_html(number_format_i18n(self::FLOW_LIFETIME)); ?> <?php esc_html_e('Sekunden', 'ahx-wp-sso'); ?></td></tr>
                    <tr><th><?php esc_html_e('Client-Sitzungsprüfung', 'ahx-wp-sso'); ?></th><td><?php echo esc_html(number_format_i18n(self::SESSION_CACHE_LIFETIME)); ?> <?php esc_html_e('Sekunden Zwischenspeicherung', 'ahx-wp-sso'); ?></td></tr>
                    <tr><th><?php esc_html_e('Plugin-Version', 'ahx-wp-sso'); ?></th><td><?php echo esc_html(AHX_WP_SSO_VERSION); ?></td></tr>
                    <tr><th><?php esc_html_e('Client-ID / Secret', 'ahx-wp-sso'); ?></th><td><?php esc_html__('Client-ID wird in der Client-Liste gezeigt; Secrets und Sitzungstoken werden aus Sicherheitsgründen nicht offengelegt.', 'ahx-wp-sso'); ?></td></tr>
                </tbody>
            </table>

            <h2><?php esc_html_e('Registrierte Clients', 'ahx-wp-sso'); ?></h2>
            <?php if (false === $clients) : ?>
                <div class="notice notice-error inline"><p><?php esc_html_e('Client-Liste konnte nicht geladen werden. Einzelheiten stehen im PHP-Fehlerprotokoll.', 'ahx-wp-sso'); ?></p></div>
            <?php elseif (empty($clients)) : ?>
                <p><?php esc_html_e('Es sind noch keine Client-Sites registriert.', 'ahx-wp-sso'); ?></p>
            <?php else : ?>
                <table class="widefat striped">
                    <thead><tr><th><?php esc_html_e('Bezeichnung', 'ahx-wp-sso'); ?></th><th>Client-ID</th><th><?php esc_html_e('Callback-URL', 'ahx-wp-sso'); ?></th><th><?php esc_html_e('Registriert am', 'ahx-wp-sso'); ?></th><th><?php esc_html_e('Aktive Sitzungen', 'ahx-wp-sso'); ?></th></tr></thead>
                    <tbody>
                    <?php foreach ($clients as $client) : ?>
                        <tr>
                            <td><?php echo esc_html($client->client_name); ?></td>
                            <td><code><?php echo esc_html($client->client_id); ?></code></td>
                            <td><code><?php echo esc_html($client->redirect_uri); ?></code></td>
                            <td><?php echo esc_html(get_date_from_gmt($client->created_at, get_option('date_format') . ' ' . get_option('time_format'))); ?></td>
                            <td><?php echo is_array($activities) ? esc_html(number_format_i18n($this->count_client_sessions($activities, $client->client_id))) : '—'; ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

            <h2><?php esc_html_e('SSO-Sitzungen', 'ahx-wp-sso'); ?></h2>
            <?php if (false === $activities) : ?>
                <div class="notice notice-error inline"><p><?php esc_html_e('Sitzungsübersicht konnte nicht geladen werden. Einzelheiten stehen im PHP-Fehlerprotokoll.', 'ahx-wp-sso'); ?></p></div>
            <?php elseif (empty($activities)) : ?>
                <p><?php esc_html_e('Es wurden noch keine Client-Sitzungen erfasst.', 'ahx-wp-sso'); ?></p>
            <?php else : ?>
                <table class="widefat striped">
                    <thead><tr><th><?php esc_html_e('Benutzer', 'ahx-wp-sso'); ?></th><th><?php esc_html_e('Client-Site', 'ahx-wp-sso'); ?></th><th><?php esc_html_e('Status', 'ahx-wp-sso'); ?></th><th><?php esc_html_e('Beginn', 'ahx-wp-sso'); ?></th><th><?php esc_html_e('Zuletzt bestätigt', 'ahx-wp-sso'); ?></th><th><?php esc_html_e('Läuft ab', 'ahx-wp-sso'); ?></th><th><?php esc_html_e('IP-Adresse', 'ahx-wp-sso'); ?></th><th><?php esc_html_e('Browser/Gerät', 'ahx-wp-sso'); ?></th><th><?php esc_html_e('SSO-Sitzung', 'ahx-wp-sso'); ?></th></tr></thead>
                    <tbody>
                    <?php foreach ($activities as $activity) :
                        $user = get_userdata(absint($activity->user_id));
                        $is_active = $this->activity_is_active($activity);
                        $host_session = $this->get_host_session_details(absint($activity->user_id), $activity->host_token_hash);
                        ?>
                        <tr>
                            <td><?php echo $user ? esc_html($user->display_name . ' (' . $user->user_email . ')') : esc_html(sprintf(__('Unbekannter Benutzer (ID %d)', 'ahx-wp-sso'), absint($activity->user_id))); ?></td>
                            <td><?php echo esc_html($activity->client_name ? $activity->client_name : __('Client widerrufen', 'ahx-wp-sso')); ?></td>
                            <td><?php echo $is_active ? '<span style="color:#008a20">' . esc_html__('Aktiv', 'ahx-wp-sso') . '</span>' : '<span style="color:#b32d2e">' . esc_html__('Beendet oder abgelaufen', 'ahx-wp-sso') . '</span>'; ?></td>
                            <td><?php echo esc_html(get_date_from_gmt($activity->created_at, get_option('date_format') . ' ' . get_option('time_format'))); ?></td>
                            <td><?php echo esc_html(get_date_from_gmt($activity->last_seen_at, get_option('date_format') . ' ' . get_option('time_format'))); ?></td>
                            <td><?php echo $activity->expires_at ? esc_html(get_date_from_gmt($activity->expires_at, get_option('date_format') . ' ' . get_option('time_format'))) : '—'; ?></td>
                            <td><?php echo $host_session && !empty($host_session['ip']) ? esc_html($host_session['ip']) : '—'; ?></td>
                            <td><?php echo $host_session && !empty($host_session['ua']) ? esc_html(wp_html_excerpt($host_session['ua'], 100, '…')) : '—'; ?></td>
                            <td><code><?php echo esc_html(substr($activity->session_id, 0, 12)); ?>…</code></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <p class="description"><?php esc_html_e('Es werden höchstens die 500 zuletzt aktualisierten Sitzungseinträge angezeigt.', 'ahx-wp-sso'); ?></p>
            <?php endif; ?>
        </div>
        <?php
    }

    private function count_client_sessions($activities, $client_id) {
        $count = 0;
        foreach ($activities as $activity) {
            if ($client_id === $activity->client_id && $this->activity_is_active($activity)) {
                ++$count;
            }
        }
        return $count;
    }

    private function activity_is_active($activity) {
        if (1 !== (int) $activity->active || 1 !== (int) $activity->sso_active
            || empty($activity->host_token_hash)
            || empty($activity->expires_at)
            || strtotime($activity->expires_at . ' UTC') <= time()) {
            return false;
        }
        return $this->host_session_is_valid(absint($activity->user_id), $activity->host_token_hash);
    }

    private function host_session_is_valid($user_id, $token_hash) {
        if (!$user_id || !preg_match('/^[a-f0-9]{64}$/', (string) $token_hash)) {
            return false;
        }
        $session = $this->get_host_session_details($user_id, $token_hash);
        if (!$session) {
            return false;
        }
        $expiration = is_array($session) && isset($session['expiration'])
            ? absint($session['expiration'])
            : 0;
        return $expiration > time();
    }

    private function get_host_session_details($user_id, $token_hash) {
        if (!$user_id || !preg_match('/^[a-f0-9]{64}$/', (string) $token_hash)) {
            return false;
        }
        $sessions = get_user_meta($user_id, 'session_tokens', true);
        if (!is_array($sessions) || !isset($sessions[$token_hash])) {
            return false;
        }
        if (is_int($sessions[$token_hash])) {
            return array('expiration' => $sessions[$token_hash]);
        }
        return is_array($sessions[$token_hash]) ? $sessions[$token_hash] : false;
    }

    public function register_settings() {
        register_setting('ahx_wp_sso_settings', 'ahx_wp_sso_config', array($this, 'sanitize_config'));
    }

    public function sanitize_config($input) {
        $input = is_array($input) ? $input : array();
        $old = $this->config();
        $mode = isset($input['mode']) ? sanitize_key($input['mode']) : 'off';
        if (!in_array($mode, array('off', 'host', 'client'), true)) {
            $mode = 'off';
        }

        $config = $old;
        $config['mode'] = $mode;
        if ('client' === $mode) {
            $host_url = isset($input['host_url']) ? esc_url_raw(trim($input['host_url'])) : (isset($old['host_url']) ? $old['host_url'] : '');
            $client_id = isset($input['client_id']) ? sanitize_text_field($input['client_id']) : (isset($old['client_id']) ? $old['client_id'] : '');
            $secret = isset($input['client_secret']) ? trim((string) $input['client_secret']) : '';
            $host_parts = wp_parse_url($host_url);
            if ('https' !== strtolower((string) wp_parse_url($host_url, PHP_URL_SCHEME))
                || !$host_parts || empty($host_parts['host'])
                || isset($host_parts['user']) || isset($host_parts['pass'])
                || isset($host_parts['query']) || isset($host_parts['fragment'])
                || !preg_match('/^[a-f0-9]{64}$/', $client_id)) {
                add_settings_error('ahx_wp_sso_config', 'invalid_client_config', __('Bitte eine HTTPS-Host-URL und eine gueltige Client-ID angeben.', 'ahx-wp-sso'));
                return $old;
            }
            $config['host_url'] = untrailingslashit($host_url);
            $config['client_id'] = $client_id;
            $config['client_secret'] = '' !== $secret ? $secret : (isset($old['client_secret']) ? $old['client_secret'] : '');
            if ('' === $config['client_secret']) {
                add_settings_error('ahx_wp_sso_config', 'missing_client_secret', __('Das Client-Secret ist erforderlich.', 'ahx-wp-sso'));
                return $old;
            }
            $break_glass_ids = isset($input['break_glass_user_ids']) && is_array($input['break_glass_user_ids'])
                ? array_map('absint', $input['break_glass_user_ids'])
                : array();
            $config['break_glass_user_ids'] = array_values(array_unique(array_filter($break_glass_ids, function($user_id) {
                $user = get_userdata($user_id);
                return $user && (is_super_admin($user_id) || is_user_member_of_blog($user_id, get_current_blog_id()));
            })));
        }
        return $config;
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        $config = $this->config();
        $callback = add_query_arg(self::ACTION, 'callback', set_url_scheme(site_url('wp-login.php', 'login'), 'https'));
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('AHX WP SSO Einstellungen', 'ahx-wp-sso'); ?></h1>
            <?php settings_errors('ahx_wp_sso_config'); ?>
            <form method="post" action="options.php">
                <?php settings_fields('ahx_wp_sso_settings'); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="ahx-wp-sso-mode"><?php esc_html_e('Betriebsart', 'ahx-wp-sso'); ?></label></th>
                        <td>
                            <select id="ahx-wp-sso-mode" name="ahx_wp_sso_config[mode]">
                                <option value="off" <?php selected($config['mode'], 'off'); ?>><?php esc_html_e('Deaktiviert (normaler WordPress-Login)', 'ahx-wp-sso'); ?></option>
                                <option value="host" <?php selected($config['mode'], 'host'); ?>><?php esc_html_e('Dedizierter SSO-Host', 'ahx-wp-sso'); ?></option>
                                <option value="client" <?php selected($config['mode'], 'client'); ?>><?php esc_html_e('Client-Site', 'ahx-wp-sso'); ?></option>
                            </select>
                        </td>
                    </tr>
                    <tr class="ahx-wp-sso-client-setting" <?php echo 'client' !== $config['mode'] ? 'hidden' : ''; ?>>
                        <th scope="row"><label for="ahx-wp-sso-host-url"><?php esc_html_e('SSO-Host-URL', 'ahx-wp-sso'); ?></label></th>
                        <td><input class="regular-text" type="url" id="ahx-wp-sso-host-url" name="ahx_wp_sso_config[host_url]" value="<?php echo esc_attr(isset($config['host_url']) ? $config['host_url'] : ''); ?>" placeholder="https://sso.example.com">
                            <p class="description"><?php esc_html_e('Wird nur in der Betriebsart „Client-Site“ benötigt.', 'ahx-wp-sso'); ?></p></td>
                    </tr>
                    <tr class="ahx-wp-sso-client-setting" <?php echo 'client' !== $config['mode'] ? 'hidden' : ''; ?>>
                        <th scope="row"><label for="ahx-wp-sso-client-id"><?php esc_html_e('Client-ID', 'ahx-wp-sso'); ?></label></th>
                        <td><input class="regular-text" type="text" id="ahx-wp-sso-client-id" name="ahx_wp_sso_config[client_id]" value="<?php echo esc_attr(isset($config['client_id']) ? $config['client_id'] : ''); ?>"></td>
                    </tr>
                    <tr class="ahx-wp-sso-client-setting" <?php echo 'client' !== $config['mode'] ? 'hidden' : ''; ?>>
                        <th scope="row"><label for="ahx-wp-sso-client-secret"><?php esc_html_e('Client-Secret', 'ahx-wp-sso'); ?></label></th>
                        <td><input class="regular-text" type="password" autocomplete="new-password" id="ahx-wp-sso-client-secret" name="ahx_wp_sso_config[client_secret]" value="" placeholder="<?php echo esc_attr__('Leer lassen, um das gespeicherte Secret beizubehalten', 'ahx-wp-sso'); ?>"></td>
                    </tr>
                    <tr class="ahx-wp-sso-client-setting" <?php echo 'client' !== $config['mode'] ? 'hidden' : ''; ?>>
                        <th scope="row"><?php esc_html_e('Callback-URL dieser Site', 'ahx-wp-sso'); ?></th>
                        <td><code><?php echo esc_html($callback); ?></code><p class="description"><?php esc_html_e('Diese URL muss am SSO-Host für diese Client-ID registriert sein.', 'ahx-wp-sso'); ?></p></td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>

            <?php if ('host' === $config['mode']) : ?>
                <hr>
                <?php $this->render_clients(); ?>
                <p>
                    <button type="button" class="button" id="ahx-wp-sso-open-client-form" aria-expanded="false" aria-controls="ahx-wp-sso-client-form">
                        <?php esc_html_e('Client-Site hinzufügen', 'ahx-wp-sso'); ?>
                    </button>
                </p>
                <div id="ahx-wp-sso-client-form" hidden>
                    <h3><?php esc_html_e('Client-Site registrieren', 'ahx-wp-sso'); ?></h3>
                    <p><?php esc_html_e('Jede Client-Site einzeln registrieren. Client-ID und Secret danach sicher in deren SSO-Einstellungen eintragen.', 'ahx-wp-sso'); ?></p>
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                        <input type="hidden" name="action" value="ahx_wp_sso_add_client">
                        <?php wp_nonce_field('ahx_wp_sso_add_client'); ?>
                        <p><label><?php esc_html_e('Bezeichnung', 'ahx-wp-sso'); ?><br><input class="regular-text" type="text" name="client_name" required></label></p>
                        <p><label><?php esc_html_e('Exakte Callback-URL der Client-Site', 'ahx-wp-sso'); ?><br><input class="large-text" type="url" name="redirect_uri" required placeholder="https://client.example.com/wp-login.php?ahx_wp_sso=callback"></label></p>
                        <?php submit_button(__('Client registrieren', 'ahx-wp-sso')); ?>
                    </form>
                </div>
            <?php endif; ?>

            <?php if ('client' === $config['mode']) : ?>
                <hr>
                <h2><?php esc_html_e('Break-Glass-Notfallzugang', 'ahx-wp-sso'); ?></h2>
                <p><?php esc_html_e('Waehlst du hier lokale Benutzer aus, duerfen diese sich mit ihrem lokalen WordPress-Passwort anmelden, wenn der SSO-Host nicht erreichbar ist. Der Notfallzugang endet, sobald der Host wieder erreichbar ist. Verwende nur dedizierte Notfallkonten mit starken Passwoertern und MFA.', 'ahx-wp-sso'); ?></p>
                <fieldset>
                    <?php $this->render_break_glass_users($config); ?>
                </fieldset>
            <?php endif; ?>
        </div>
        <script>
        document.addEventListener('DOMContentLoaded', function () {
            var mode = document.getElementById('ahx-wp-sso-mode');
            var clientSettings = document.querySelectorAll('.ahx-wp-sso-client-setting');
            if (mode) {
                var updateClientSettings = function () {
                    var show = 'client' === mode.value;
                    clientSettings.forEach(function (row) {
                        row.hidden = !show;
                    });
                };
                mode.addEventListener('change', updateClientSettings);
                updateClientSettings();
            }

            var openClientForm = document.getElementById('ahx-wp-sso-open-client-form');
            var clientForm = document.getElementById('ahx-wp-sso-client-form');
            if (openClientForm && clientForm) {
                openClientForm.addEventListener('click', function () {
                    var isOpen = !clientForm.hidden;
                    clientForm.hidden = isOpen;
                    openClientForm.setAttribute('aria-expanded', isOpen ? 'false' : 'true');
                    openClientForm.textContent = isOpen
                        ? '<?php echo esc_js(__('Client-Site hinzufügen', 'ahx-wp-sso')); ?>'
                        : '<?php echo esc_js(__('Formular schließen', 'ahx-wp-sso')); ?>';
                });
            }
        });
        </script>
        <?php
    }

    public function add_client() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unzureichende Berechtigung.', 'ahx-wp-sso'), '', array('response' => 403));
        }
        check_admin_referer('ahx_wp_sso_add_client');
        if ('host' !== $this->config()['mode']) {
            wp_die(esc_html__('Die Site ist nicht als SSO-Host konfiguriert.', 'ahx-wp-sso'), '', array('response' => 400));
        }

        $name = isset($_POST['client_name']) ? sanitize_text_field(wp_unslash($_POST['client_name'])) : '';
        $redirect = isset($_POST['redirect_uri']) ? esc_url_raw(trim(wp_unslash($_POST['redirect_uri']))) : '';
        $parts = wp_parse_url($redirect);
        if ('' === $name || !$parts || 'https' !== strtolower(isset($parts['scheme']) ? $parts['scheme'] : '')
            || empty($parts['host']) || !isset($parts['query'])
            || !preg_match('/(?:^|&)ahx_wp_sso=callback(?:&|$)/', $parts['query'])) {
            wp_die(esc_html__('Bitte Bezeichnung und gueltige HTTPS-Callback-URL angeben.', 'ahx-wp-sso'), '', array('response' => 400));
        }

        $client_id = bin2hex(random_bytes(32));
        $secret = bin2hex(random_bytes(32));
        global $wpdb;
        $inserted = $wpdb->insert(
            $this->table('clients'),
            array(
                'client_id' => $client_id,
                'secret_hash' => hash('sha256', $secret),
                'client_name' => $name,
                'redirect_uri' => $redirect,
                'created_at' => gmdate('Y-m-d H:i:s'),
            ),
            array('%s', '%s', '%s', '%s', '%s')
        );
        if (false === $inserted) {
            error_log('AHX WP SSO could not register a client: ' . $wpdb->last_error);
            wp_die(esc_html__('Client konnte nicht gespeichert werden. Details stehen im Server-Log.', 'ahx-wp-sso'), '', array('response' => 500));
        }

        set_transient('ahx_wp_sso_new_client_' . get_current_user_id(), array(
            'name' => $name,
            'client_id' => $client_id,
            'client_secret' => $secret,
            'redirect_uri' => $redirect,
        ), 10 * MINUTE_IN_SECONDS);
        wp_safe_redirect(add_query_arg('client_created', '1', admin_url('options-general.php?page=ahx-wp-sso')));
        exit;
    }

    public function remove_client() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unzureichende Berechtigung.', 'ahx-wp-sso'), '', array('response' => 403));
        }
        $client_id = isset($_POST['client_id']) ? sanitize_text_field(wp_unslash($_POST['client_id'])) : '';
        check_admin_referer('ahx_wp_sso_remove_client_' . $client_id);
        if ('host' !== $this->config()['mode'] || !preg_match('/^[a-f0-9]{64}$/', $client_id)) {
            wp_die(esc_html__('Ungueltiger Client.', 'ahx-wp-sso'), '', array('response' => 400));
        }

        global $wpdb;
        $deleted = $wpdb->delete($this->table('clients'), array('client_id' => $client_id), array('%s'));
        if (false === $deleted) {
            error_log('AHX WP SSO could not remove a client: ' . $wpdb->last_error);
            wp_die(esc_html__('Client konnte nicht entfernt werden. Details stehen im Server-Log.', 'ahx-wp-sso'), '', array('response' => 500));
        }
        $branding = get_option('ahx_wp_sso_client_branding', array());
        if (is_array($branding) && isset($branding[$client_id])) {
            unset($branding[$client_id]);
            update_option('ahx_wp_sso_client_branding', $branding, false);
        }
        $codes_deleted = $wpdb->delete($this->table('codes'), array('client_id' => $client_id), array('%s'));
        if (false === $codes_deleted) {
            error_log('AHX WP SSO could not remove authorization codes for revoked client: ' . $wpdb->last_error);
        }
        $sessions_revoked = $wpdb->update($this->table('client_activity'), array(
            'active' => 0,
            'revoked_at' => gmdate('Y-m-d H:i:s'),
        ), array('client_id' => $client_id, 'active' => 1), array('%d', '%s'), array('%s', '%d'));
        if (false === $sessions_revoked) {
            error_log('AHX WP SSO could not revoke sessions for removed client: ' . $wpdb->last_error);
        }
        wp_safe_redirect(admin_url('options-general.php?page=ahx-wp-sso'));
        exit;
    }

    public function save_client_branding() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unzureichende Berechtigung.', 'ahx-wp-sso'), '', array('response' => 403));
        }
        $client_id = isset($_POST['client_id']) ? sanitize_text_field(wp_unslash($_POST['client_id'])) : '';
        check_admin_referer('ahx_wp_sso_save_client_branding_' . $client_id);
        if ('host' !== $this->config()['mode'] || !preg_match('/^[a-f0-9]{64}$/', $client_id) || !$this->get_client($client_id)) {
            wp_die(esc_html__('Ungueltiger Client.', 'ahx-wp-sso'), '', array('response' => 400));
        }

        $display_name = isset($_POST['display_name'])
            ? sanitize_text_field(wp_unslash($_POST['display_name']))
            : '';
        $logo_url = isset($_POST['logo_url']) ? esc_url_raw(trim(wp_unslash($_POST['logo_url']))) : '';
        $accent_color = isset($_POST['accent_color']) ? sanitize_hex_color(wp_unslash($_POST['accent_color'])) : '';
        if ('' !== $logo_url && 'https' !== strtolower((string) wp_parse_url($logo_url, PHP_URL_SCHEME))) {
            wp_die(esc_html__('Die Logo-URL muss HTTPS verwenden.', 'ahx-wp-sso'), '', array('response' => 400));
        }
        if (!$accent_color) {
            $accent_color = '#2271b1';
        }

        $branding = get_option('ahx_wp_sso_client_branding', array());
        if (!is_array($branding)) {
            $branding = array();
        }
        $branding[$client_id] = array(
            'display_name' => $display_name,
            'logo_url' => $logo_url,
            'accent_color' => $accent_color,
        );
        update_option('ahx_wp_sso_client_branding', $branding, false);
        wp_safe_redirect(add_query_arg('branding_saved', '1', admin_url('options-general.php?page=ahx-wp-sso')));
        exit;
    }

    private function get_client_branding($client_id) {
        $all_branding = get_option('ahx_wp_sso_client_branding', array());
        $branding = is_array($all_branding) && isset($all_branding[$client_id]) && is_array($all_branding[$client_id])
            ? $all_branding[$client_id]
            : array();
        $logo_url = isset($branding['logo_url']) ? esc_url_raw($branding['logo_url']) : '';
        if ('' !== $logo_url && 'https' !== strtolower((string) wp_parse_url($logo_url, PHP_URL_SCHEME))) {
            $logo_url = '';
        }
        $accent_color = isset($branding['accent_color']) ? sanitize_hex_color($branding['accent_color']) : '';

        return array(
            'display_name' => isset($branding['display_name']) ? sanitize_text_field($branding['display_name']) : '',
            'logo_url' => $logo_url,
            'accent_color' => $accent_color ? $accent_color : '#2271b1',
        );
    }

    private function render_clients() {
        $new_client = get_transient('ahx_wp_sso_new_client_' . get_current_user_id());
        if ($new_client) {
            delete_transient('ahx_wp_sso_new_client_' . get_current_user_id());
            echo '<div class="notice notice-success"><p><strong>' . esc_html__('Client angelegt. Das Secret wird nur einmal angezeigt:', 'ahx-wp-sso') . '</strong></p><p>';
            echo esc_html__('Client-ID:', 'ahx-wp-sso') . ' <code>' . esc_html($new_client['client_id']) . '</code><br>';
            echo esc_html__('Client-Secret:', 'ahx-wp-sso') . ' <code>' . esc_html($new_client['client_secret']) . '</code><br>';
            echo esc_html__('Callback-URL:', 'ahx-wp-sso') . ' <code>' . esc_html($new_client['redirect_uri']) . '</code></p></div>';
        }

        global $wpdb;
        $rows = $wpdb->get_results("SELECT client_id, client_name, redirect_uri, created_at FROM " . $this->table('clients') . ' ORDER BY created_at DESC');
        if (!empty($wpdb->last_error)) {
            error_log('AHX WP SSO could not list clients: ' . $wpdb->last_error);
            echo '<div class="notice notice-error"><p>' . esc_html__('Client-Liste konnte nicht geladen werden. Details stehen im Server-Log.', 'ahx-wp-sso') . '</p></div>';
            return;
        }
        echo '<h3>' . esc_html__('Registrierte Clients', 'ahx-wp-sso') . '</h3>';
        if (isset($_GET['branding_saved']) && '1' === sanitize_text_field(wp_unslash($_GET['branding_saved']))) {
            echo '<div class="notice notice-success inline"><p>' . esc_html__('Client-Darstellung gespeichert.', 'ahx-wp-sso') . '</p></div>';
        }
        if (!$rows) {
            echo '<p>' . esc_html__('Noch keine Clients registriert.', 'ahx-wp-sso') . '</p>';
            return;
        }
        echo '<p>' . esc_html__('Logo, Anzeigename und Akzentfarbe werden auf der Host-Anmeldeseite für den jeweiligen Client verwendet. Auch bei einer bestehenden Host-Anmeldung erscheint eine Bestätigung mit Client-Darstellung.', 'ahx-wp-sso') . '</p>';
        echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Bezeichnung', 'ahx-wp-sso') . '</th><th>Client-ID</th><th>Callback-URL</th><th>' . esc_html__('Anmeldedarstellung', 'ahx-wp-sso') . '</th><th>' . esc_html__('Aktionen', 'ahx-wp-sso') . '</th></tr></thead><tbody>';
        foreach ($rows as $row) {
            $branding = $this->get_client_branding($row->client_id);
            echo '<tr><td>' . esc_html($row->client_name) . '</td><td><code>' . esc_html($row->client_id) . '</code></td><td><code>' . esc_html($row->redirect_uri) . '</code></td><td>';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="ahx_wp_sso_save_client_branding"><input type="hidden" name="client_id" value="' . esc_attr($row->client_id) . '">';
            wp_nonce_field('ahx_wp_sso_save_client_branding_' . $row->client_id);
            echo '<p><label>' . esc_html__('Anzeigename', 'ahx-wp-sso') . '<br><input class="regular-text" type="text" name="display_name" value="' . esc_attr($branding['display_name']) . '" placeholder="' . esc_attr($row->client_name) . '"></label></p>';
            echo '<p><label>' . esc_html__('Logo-URL (HTTPS)', 'ahx-wp-sso') . '<br><input class="regular-text" type="url" name="logo_url" value="' . esc_attr($branding['logo_url']) . '" placeholder="https://example.com/logo.png"></label></p>';
            echo '<p><label>' . esc_html__('Akzentfarbe', 'ahx-wp-sso') . ' <input type="color" name="accent_color" value="' . esc_attr($branding['accent_color']) . '"></label></p>';
            submit_button(__('Darstellung speichern', 'ahx-wp-sso'), 'secondary', 'submit', false);
            echo '</form></td><td><form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="ahx_wp_sso_remove_client"><input type="hidden" name="client_id" value="' . esc_attr($row->client_id) . '">';
            wp_nonce_field('ahx_wp_sso_remove_client_' . $row->client_id);
            submit_button(__('Client widerrufen', 'ahx-wp-sso'), 'delete', 'submit', false, array('onclick' => "return confirm('" . esc_js(__('Client wirklich widerrufen?', 'ahx-wp-sso')) . "');"));
            echo '</form></td></tr>';
        }
        echo '</tbody></table>';
    }

    private function render_break_glass_users($config) {
        $allowed_ids = isset($config['break_glass_user_ids']) && is_array($config['break_glass_user_ids'])
            ? array_map('absint', $config['break_glass_user_ids'])
            : array();
        $users = get_users(array(
            'orderby' => 'ID',
            'order' => 'ASC',
            'fields' => array('ID', 'user_login', 'user_email'),
            'number' => -1,
        ));
        if (!empty($users)) {
            foreach ($users as $user) {
                if (!is_super_admin($user->ID) && !is_user_member_of_blog($user->ID, get_current_blog_id())) {
                    continue;
                }
                printf(
                    '<label style="display:block;margin:6px 0"><input type="checkbox" name="ahx_wp_sso_config[break_glass_user_ids][]" value="%1$d" %2$s> %3$s <code>%4$s</code> — %5$s</label>',
                    absint($user->ID),
                    checked(in_array(absint($user->ID), $allowed_ids, true), true, false),
                    esc_html($user->user_login),
                    esc_html($user->user_email),
                    sprintf(esc_html__('Benutzer-ID %d', 'ahx-wp-sso'), absint($user->ID))
                );
            }
        }
        echo '<p class="description">' . esc_html__('Nicht ausgewaehlte Konten koennen sich auch bei Host-Ausfall nicht lokal anmelden.', 'ahx-wp-sso') . '</p>';
    }

    public function show_setup_notice() {
        if (!current_user_can('manage_options') || !is_multisite() || !$this->is_network_active()) {
            return;
        }
        if ('off' !== $this->config()['mode']) {
            return;
        }
        echo '<div class="notice notice-info"><p>' . esc_html__('AHX WP SSO ist noch nicht eingerichtet. Waehlen Sie unter Einstellungen → AHX WP SSO die Betriebsart.', 'ahx-wp-sso') . '</p></div>';
    }

    public function register_rest_routes() {
        register_rest_route(self::REST_NAMESPACE, '/token', array(
            'methods' => 'POST',
            'callback' => array($this, 'rest_token'),
            'permission_callback' => '__return_true',
        ));
        register_rest_route(self::REST_NAMESPACE, '/session', array(
            'methods' => 'POST',
            'callback' => array($this, 'rest_session'),
            'permission_callback' => '__return_true',
        ));
        register_rest_route(self::REST_NAMESPACE, '/health', array(
            'methods' => 'GET',
            'callback' => array($this, 'rest_health'),
            'permission_callback' => '__return_true',
        ));
    }

    public function rest_health() {
        if ('host' !== $this->config()['mode']) {
            return new WP_Error('ahx_sso_not_host', __('Diese Site ist nicht als SSO-Host konfiguriert.', 'ahx-wp-sso'), array('status' => 404));
        }
        return rest_ensure_response(array('service' => 'ahx-wp-sso', 'status' => 'available'));
    }

    public function handle_login() {
        $action = isset($_GET[self::ACTION]) ? sanitize_key(wp_unslash($_GET[self::ACTION])) : '';
        $login_action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';

        if ('logout' === $login_action) {
            $this->handle_logout($action);
            return;
        }

        $mode = $this->config()['mode'];
        if ('host' === $mode && 'authorize' === $action) {
            $this->authorize();
            return;
        }
        if ('client' === $mode && 'callback' === $action) {
            $this->client_callback();
            return;
        }
        if ('client' === $mode && !is_user_logged_in()) {
            $this->require_https();
            if (isset($_SERVER['REQUEST_METHOD']) && 'GET' === $_SERVER['REQUEST_METHOD']
                && in_array($login_action, array('', 'login'), true)) {
                if ($this->is_host_available()) {
                    $this->start_client_login();
                }
            } elseif (!in_array($login_action, array('', 'login'), true)) {
                $this->deny(__('Registrierung und Passwortverwaltung erfolgen ueber den SSO-Host.', 'ahx-wp-sso'), 403);
            }
        }
    }

    private function start_client_login() {
        $this->require_https();
        $config = $this->config();
        if (empty($config['host_url']) || empty($config['client_id']) || empty($config['client_secret'])) {
            $this->deny(__('Diese Client-Site ist nicht vollstaendig konfiguriert.', 'ahx-wp-sso'), 500);
        }

        $state = bin2hex(random_bytes(32));
        $verifier = bin2hex(random_bytes(32));
        $callback = $this->callback_url();
        $redirect = isset($_GET['redirect_to']) ? wp_unslash($_GET['redirect_to']) : '';
        $redirect = wp_validate_redirect($redirect, home_url('/'));
        set_transient($this->flow_key($state), array('verifier' => $verifier, 'redirect' => $redirect), self::FLOW_LIFETIME);
        setcookie($this->state_cookie_name($state), $state, array(
            'expires' => time() + self::FLOW_LIFETIME,
            'path' => defined('COOKIEPATH') && COOKIEPATH ? COOKIEPATH : '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ));
        $authorize_url = add_query_arg(array(
            self::ACTION => 'authorize',
            'client_id' => $config['client_id'],
            'redirect_uri' => $callback,
            'state' => $state,
            'code_challenge' => $this->pkce_challenge($verifier),
        ), trailingslashit($config['host_url']) . 'wp-login.php');
        wp_redirect($authorize_url, 302, 'AHX WP SSO');
        exit;
    }

    private function authorize() {
        $this->require_https();
        $client_id = isset($_GET['client_id']) ? sanitize_text_field(wp_unslash($_GET['client_id'])) : '';
        $redirect = isset($_GET['redirect_uri']) ? esc_url_raw(wp_unslash($_GET['redirect_uri'])) : '';
        $state = isset($_GET['state']) ? sanitize_text_field(wp_unslash($_GET['state'])) : '';
        $challenge = isset($_GET['code_challenge']) ? sanitize_text_field(wp_unslash($_GET['code_challenge'])) : '';
        $client = $this->get_client($client_id);
        if (!$client || !$this->same_url($client->redirect_uri, $redirect)
            || !preg_match('/^[a-f0-9]{64}$/', $state)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/', $challenge)) {
            $this->deny(__('Unbekannte Client-Site oder ungueltige Anmeldeanfrage.', 'ahx-wp-sso'), 400);
        }

        if (!is_user_logged_in()) {
            $request_url = add_query_arg(wp_unslash($_GET), set_url_scheme(site_url('wp-login.php', 'login'), 'https'));
            wp_safe_redirect(set_url_scheme(wp_login_url($request_url), 'https'));
            exit;
        }

        $continue = isset($_GET['ahx_sso_continue'])
            ? sanitize_text_field(wp_unslash($_GET['ahx_sso_continue']))
            : '';
        if ('1' !== $continue) {
            $this->render_client_continue_dialog($client, $state, $challenge);
        }

        $user = wp_get_current_user();
        if (!$user->exists() || !is_email($user->user_email)) {
            $this->deny(__('Das SSO-Konto hat keine gueltige E-Mail-Adresse.', 'ahx-wp-sso'), 403);
        }

        $host_token = wp_get_session_token();
        if ('' === $host_token) {
            $this->deny(__('Die zentrale WordPress-Sitzung konnte nicht ermittelt werden.', 'ahx-wp-sso'), 403);
        }
        global $wpdb;
        $host_sessions = $this->table('host_sessions');
        $existing_session = $wpdb->get_row($wpdb->prepare(
            "SELECT active FROM $host_sessions WHERE user_id = %d AND host_token_hash = %s",
            $user->ID,
            hash('sha256', $host_token)
        ));
        if (!empty($wpdb->last_error)) {
            error_log('AHX WP SSO could not inspect the current host session: ' . $wpdb->last_error);
            $this->deny(__('Die zentrale Sitzung konnte nicht geprueft werden.', 'ahx-wp-sso'), 500);
        }
        if ($existing_session && 0 === (int) $existing_session->active) {
            WP_Session_Tokens::get_instance($user->ID)->destroy($host_token);
            wp_clear_auth_cookie();
            $request_url = add_query_arg(wp_unslash($_GET), set_url_scheme(site_url('wp-login.php', 'login'), 'https'));
            wp_safe_redirect(set_url_scheme(wp_login_url($request_url), 'https'));
            exit;
        }

        $host_session_id = $this->ensure_host_session($user->ID);
        if (!$host_session_id) {
            $this->deny(__('Die zentrale Sitzung konnte nicht gespeichert werden.', 'ahx-wp-sso'), 500);
        }

        $code = bin2hex(random_bytes(32));
        $inserted = $wpdb->insert(
            $this->table('codes'),
            array(
                'code_hash' => hash('sha256', $code),
                'client_id' => $client_id,
                'user_id' => $user->ID,
                'host_session_id' => $host_session_id,
                'code_challenge' => $challenge,
                'expires_at' => gmdate('Y-m-d H:i:s', time() + self::FLOW_LIFETIME),
            ),
            array('%s', '%s', '%d', '%s', '%s', '%s')
        );
        if (false === $inserted) {
            error_log('AHX WP SSO could not store an authorization code: ' . $wpdb->last_error);
            $this->deny(__('Die Anmeldung konnte nicht vorbereitet werden. Bitte erneut versuchen.', 'ahx-wp-sso'), 500);
        }
        wp_redirect(add_query_arg(array('code' => $code, 'state' => $state), $redirect), 302, 'AHX WP SSO');
        exit;
    }

    private function render_client_continue_dialog($client, $state, $challenge) {
        $branding = $this->get_client_branding($client->client_id);
        $display_name = '' !== $branding['display_name']
            ? $branding['display_name']
            : $client->client_name;
        $user = wp_get_current_user();
        $authorize_url = add_query_arg(array(
            self::ACTION => 'authorize',
            'client_id' => $client->client_id,
            'redirect_uri' => $client->redirect_uri,
            'state' => $state,
            'code_challenge' => $challenge,
        ), set_url_scheme(site_url('wp-login.php', 'login'), 'https'));
        $continue_url = add_query_arg('ahx_sso_continue', '1', $authorize_url);
        $logout_url = wp_logout_url($authorize_url);

        nocache_headers();
        status_header(200);
        ?><!doctype html>
        <html <?php language_attributes(); ?>>
        <head>
            <meta charset="<?php bloginfo('charset'); ?>">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title><?php echo esc_html(sprintf(__('Weiter zu %s', 'ahx-wp-sso'), $display_name)); ?></title>
            <style>
                :root { color-scheme: light; }
                body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; box-sizing: border-box; background: #f0f2f5; color: #1d2327; font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
                .ahx-sso-card { width: min(100%, 420px); box-sizing: border-box; padding: 32px; border-radius: 12px; background: #fff; box-shadow: 0 8px 30px rgba(0,0,0,.12); text-align: center; }
                .ahx-sso-logo { display: block; max-width: 220px; max-height: 80px; width: auto; height: auto; margin: 0 auto 20px; }
                .ahx-sso-card h1 { margin: 0 0 8px; font-size: 24px; line-height: 1.25; }
                .ahx-sso-card p { margin: 8px 0 20px; color: #50575e; overflow-wrap: anywhere; }
                .ahx-sso-button { display: block; width: 100%; box-sizing: border-box; padding: 11px 16px; border: 0; border-radius: 6px; background: <?php echo esc_html($branding['accent_color']); ?>; color: #fff; font-size: 16px; font-weight: 600; text-decoration: none; cursor: pointer; }
                .ahx-sso-button:hover, .ahx-sso-button:focus { filter: brightness(.92); color: #fff; }
                .ahx-sso-switch { display: inline-block; margin-top: 16px; color: <?php echo esc_html($branding['accent_color']); ?>; }
            </style>
        </head>
        <body>
            <main class="ahx-sso-card">
                <?php if ('' !== $branding['logo_url']) : ?>
                    <img class="ahx-sso-logo" src="<?php echo esc_url($branding['logo_url']); ?>" alt="<?php echo esc_attr($display_name); ?>">
                <?php endif; ?>
                <h1><?php echo esc_html(sprintf(__('Weiter zu %s', 'ahx-wp-sso'), $display_name)); ?></h1>
                <p><?php echo esc_html(sprintf(__('Angemeldet als %s', 'ahx-wp-sso'), $user->user_login)); ?></p>
                <p><?php esc_html_e('Mit deiner bestehenden Anmeldung kannst du sicher fortfahren.', 'ahx-wp-sso'); ?></p>
                <a class="ahx-sso-button" href="<?php echo esc_url($continue_url); ?>"><?php esc_html_e('Weiter', 'ahx-wp-sso'); ?></a>
                <a class="ahx-sso-switch" href="<?php echo esc_url($logout_url); ?>"><?php esc_html_e('Mit einem anderen Konto anmelden', 'ahx-wp-sso'); ?></a>
            </main>
        </body>
        </html><?php
        exit;
    }

    public function rest_token($request) {
        if ('host' !== $this->config()['mode'] || !$this->is_https_request()) {
            return new WP_Error('ahx_sso_unavailable', __('SSO-Host nicht verfuegbar.', 'ahx-wp-sso'), array('status' => 403));
        }
        $client = $this->authenticate_client($request);
        if (is_wp_error($client)) {
            return $client;
        }

        $code = sanitize_text_field((string) $request->get_param('code'));
        $verifier = sanitize_text_field((string) $request->get_param('code_verifier'));
        if (!preg_match('/^[a-f0-9]{64}$/', $code) || !preg_match('/^[a-f0-9]{64}$/', $verifier)) {
            return new WP_Error('ahx_sso_invalid_grant', __('Ungueltiger Anmeldecode.', 'ahx-wp-sso'), array('status' => 400));
        }

        global $wpdb;
        $codes = $this->table('codes');
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT user_id, host_session_id, code_challenge FROM $codes WHERE code_hash = %s AND client_id = %s AND expires_at > %s AND used_at IS NULL",
            hash('sha256', $code),
            $client->client_id,
            gmdate('Y-m-d H:i:s')
        ));
        if (!empty($wpdb->last_error)) {
            error_log('AHX WP SSO could not read an authorization code: ' . $wpdb->last_error);
            return new WP_Error('ahx_sso_storage_error', __('Anmeldecode konnte nicht geprueft werden.', 'ahx-wp-sso'), array('status' => 500));
        }
        if (!$row || !hash_equals($row->code_challenge, $this->pkce_challenge($verifier))) {
            return new WP_Error('ahx_sso_invalid_grant', __('Anmeldecode ungueltig oder abgelaufen.', 'ahx-wp-sso'), array('status' => 400));
        }
        $used = $wpdb->update($codes, array('used_at' => gmdate('Y-m-d H:i:s')), array(
            'code_hash' => hash('sha256', $code),
            'client_id' => $client->client_id,
            'used_at' => null,
        ), array('%s'), array('%s', '%s', '%s'));
        if (false === $used) {
            error_log('AHX WP SSO could not consume an authorization code: ' . $wpdb->last_error);
            return new WP_Error('ahx_sso_storage_error', __('Anmeldecode konnte nicht verbraucht werden.', 'ahx-wp-sso'), array('status' => 500));
        }
        if (1 !== $used) {
            return new WP_Error('ahx_sso_invalid_grant', __('Anmeldecode wurde bereits verwendet.', 'ahx-wp-sso'), array('status' => 400));
        }

        $user = get_user_by('id', absint($row->user_id));
        if (!$user || !is_email($user->user_email)) {
            return new WP_Error('ahx_sso_invalid_user', __('SSO-Benutzer nicht verfuegbar.', 'ahx-wp-sso'), array('status' => 403));
        }
        $session_id = isset($row->host_session_id) ? (string) $row->host_session_id : '';
        if (!preg_match('/^[a-f0-9]{64}$/', $session_id)) {
            return new WP_Error('ahx_sso_storage_error', __('SSO-Sitzung konnte nicht gespeichert werden.', 'ahx-wp-sso'), array('status' => 500));
        }
        $host_session = $wpdb->get_row($wpdb->prepare(
            "SELECT user_id, active, host_token_hash FROM " . $this->table('host_sessions') . " WHERE session_id = %s",
            $session_id
        ));
        if (!empty($wpdb->last_error)) {
            error_log('AHX WP SSO could not validate the host session for an authorization code: ' . $wpdb->last_error);
            return new WP_Error('ahx_sso_storage_error', __('SSO-Sitzung konnte nicht geprueft werden.', 'ahx-wp-sso'), array('status' => 500));
        }
        if (
            !$host_session
            || absint($host_session->user_id) !== absint($user->ID)
            || 1 !== (int) $host_session->active
            || !$this->host_session_is_valid(absint($host_session->user_id), $host_session->host_token_hash)
        ) {
            return new WP_Error('ahx_sso_invalid_grant', __('Die zentrale Anmeldung ist nicht mehr aktiv. Bitte erneut anmelden.', 'ahx-wp-sso'), array('status' => 400));
        }
        $client_session_id = bin2hex(random_bytes(32));
        $created_at = gmdate('Y-m-d H:i:s');
        $activity_created = $wpdb->insert($this->table('client_activity'), array(
            'client_session_id' => $client_session_id,
            'client_id' => $client->client_id,
            'session_id' => $session_id,
            'user_id' => $user->ID,
            'active' => 1,
            'created_at' => $created_at,
            'last_seen_at' => $created_at,
            'expires_at' => null,
        ), array('%s', '%s', '%s', '%d', '%d', '%s', '%s', '%s'));
        if (false === $activity_created) {
            error_log('AHX WP SSO could not record client activity: ' . $wpdb->last_error);
            return new WP_Error('ahx_sso_storage_error', __('Client-Sitzung konnte nicht protokolliert werden.', 'ahx-wp-sso'), array('status' => 500));
        }
        return rest_ensure_response(array(
            'email' => strtolower(trim($user->user_email)),
            'session_id' => $session_id,
            'client_session_id' => $client_session_id,
        ));
    }

    public function rest_session($request) {
        if ('host' !== $this->config()['mode'] || !$this->is_https_request()) {
            return new WP_Error('ahx_sso_unavailable', __('SSO-Host nicht verfuegbar.', 'ahx-wp-sso'), array('status' => 403));
        }
        $client = $this->authenticate_client($request);
        if (is_wp_error($client)) {
            return $client;
        }
        $session_id = sanitize_text_field((string) $request->get_param('session_id'));
        $client_session_id = sanitize_text_field((string) $request->get_param('client_session_id'));
        $operation = sanitize_key((string) $request->get_param('operation'));
        if (!preg_match('/^[a-f0-9]{64}$/', $session_id)
            || !preg_match('/^[a-f0-9]{64}$/', $client_session_id)
            || !in_array($operation, array('check', 'register', 'revoke', 'revoke_all', 'revoke_local'), true)) {
            return new WP_Error('ahx_sso_invalid_session', __('Ungueltige SSO-Sitzung.', 'ahx-wp-sso'), array('status' => 400));
        }

        global $wpdb;
        $table = $this->table('host_sessions');
        $activity_table = $this->table('client_activity');
        $activity = $wpdb->get_row($wpdb->prepare(
            "SELECT user_id, active, expires_at FROM $activity_table WHERE client_session_id = %s AND client_id = %s AND session_id = %s",
            $client_session_id,
            $client->client_id,
            $session_id
        ));
        if (!empty($wpdb->last_error)) {
            error_log('AHX WP SSO could not inspect client activity: ' . $wpdb->last_error);
            return new WP_Error('ahx_sso_storage_error', __('Client-Sitzung konnte nicht geprueft werden.', 'ahx-wp-sso'), array('status' => 500));
        }
        if (!$activity) {
            return rest_ensure_response(array('active' => false));
        }
        $session = $wpdb->get_row($wpdb->prepare("SELECT user_id, active, host_token_hash FROM $table WHERE session_id = %s", $session_id));
        if (!empty($wpdb->last_error)) {
            error_log('AHX WP SSO could not inspect a session: ' . $wpdb->last_error);
            return new WP_Error('ahx_sso_storage_error', __('SSO-Sitzung konnte nicht geprueft werden.', 'ahx-wp-sso'), array('status' => 500));
        }
        if (!$session || absint($session->user_id) !== absint($activity->user_id)) {
            return rest_ensure_response(array('active' => false));
        }

        $host_session_valid = 1 === (int) $session->active
            && $this->host_session_is_valid(absint($session->user_id), $session->host_token_hash);
        $client_session_expired = empty($activity->expires_at)
            || strtotime($activity->expires_at . ' UTC') <= time();
        if (('check' === $operation && (!$host_session_valid || empty($activity->active) || $client_session_expired))
            || ('register' === $operation && (!$host_session_valid || empty($activity->active)))) {
            if (!$host_session_valid) {
                $host_updated = $wpdb->update($table, array(
                    'active' => 0,
                    'revoked_at' => gmdate('Y-m-d H:i:s'),
                ), array('session_id' => $session_id, 'active' => 1), array('%d', '%s'), array('%s', '%d'));
                if (false === $host_updated) {
                    error_log('AHX WP SSO could not expire invalid host session: ' . $wpdb->last_error);
                    return new WP_Error('ahx_sso_storage_error', __('SSO-Sitzung konnte nicht abgelaufen markiert werden.', 'ahx-wp-sso'), array('status' => 500));
                }
            }
            $activity_updated = $wpdb->update($activity_table, array(
                'active' => 0,
                'revoked_at' => gmdate('Y-m-d H:i:s'),
            ), array('client_session_id' => $client_session_id, 'client_id' => $client->client_id, 'active' => 1), array('%d', '%s'), array('%s', '%s', '%d'));
            if (false === $activity_updated) {
                error_log('AHX WP SSO could not expire client session: ' . $wpdb->last_error);
                return new WP_Error('ahx_sso_storage_error', __('Client-Sitzung konnte nicht abgelaufen markiert werden.', 'ahx-wp-sso'), array('status' => 500));
            }
            return rest_ensure_response(array('active' => false));
        }

        if ('register' === $operation) {
            $expires_at = absint($request->get_param('expires_at'));
            if ($expires_at <= time() || $expires_at > time() + 30 * DAY_IN_SECONDS) {
                return new WP_Error('ahx_sso_invalid_expiration', __('Ungueltige Sitzungsablaufzeit.', 'ahx-wp-sso'), array('status' => 400));
            }
            $updated = $wpdb->update($activity_table, array(
                'expires_at' => gmdate('Y-m-d H:i:s', $expires_at),
                'last_seen_at' => gmdate('Y-m-d H:i:s'),
            ), array('client_session_id' => $client_session_id, 'client_id' => $client->client_id, 'active' => 1),
                array('%s', '%s'), array('%s', '%s', '%d'));
            if (false === $updated) {
                error_log('AHX WP SSO could not update client session expiration: ' . $wpdb->last_error);
                return new WP_Error('ahx_sso_storage_error', __('Sitzungsablauf konnte nicht gespeichert werden.', 'ahx-wp-sso'), array('status' => 500));
            }
            return rest_ensure_response(array('active' => $host_session_valid && 1 === (int) $activity->active));
        }

        if ('revoke_local' === $operation) {
            $updated = $wpdb->update($activity_table, array(
                'active' => 0,
                'revoked_at' => gmdate('Y-m-d H:i:s'),
            ), array('client_session_id' => $client_session_id, 'client_id' => $client->client_id, 'active' => 1),
                array('%d', '%s'),
                array('%s', '%s', '%d')
            );
            if (false === $updated) {
                error_log('AHX WP SSO could not revoke local client session: ' . $wpdb->last_error);
                return new WP_Error('ahx_sso_storage_error', __('Client-Sitzung konnte nicht abgemeldet werden.', 'ahx-wp-sso'), array('status' => 500));
            }
            return rest_ensure_response(array('active' => false));
        }

        if (in_array($operation, array('revoke', 'revoke_all'), true)) {
            $where = 'revoke_all' === $operation
                ? array('user_id' => absint($session->user_id), 'active' => 1)
                : array('session_id' => $session_id, 'active' => 1);
            $where_formats = 'revoke_all' === $operation ? array('%d', '%d') : array('%s', '%d');
            $updated = $wpdb->update($table, array(
                'active' => 0,
                'revoked_at' => gmdate('Y-m-d H:i:s'),
            ), $where, array('%d', '%s'), $where_formats);
            if (false !== $updated) {
                $activity_where = 'revoke_all' === $operation
                    ? array('user_id' => absint($session->user_id), 'active' => 1)
                    : array('session_id' => $session_id, 'active' => 1);
                $activity_where_formats = 'revoke_all' === $operation ? array('%d', '%d') : array('%s', '%d');
                $updated = $wpdb->update($activity_table, array(
                    'active' => 0,
                    'revoked_at' => gmdate('Y-m-d H:i:s'),
                ), $activity_where, array('%d', '%s'), $activity_where_formats);
            }
            if (false === $updated) {
                error_log('AHX WP SSO could not revoke sessions: ' . $wpdb->last_error);
                return new WP_Error('ahx_sso_storage_error', __('SSO-Sitzung konnte nicht abgemeldet werden.', 'ahx-wp-sso'), array('status' => 500));
            }
            if ('revoke_all' === $operation) {
                WP_Session_Tokens::get_instance(absint($session->user_id))->destroy_all();
            }
            return rest_ensure_response(array('active' => false));
        }

        if (1 === (int) $activity->active && $host_session_valid) {
            $updated = $wpdb->update($activity_table, array('last_seen_at' => gmdate('Y-m-d H:i:s')), array(
                'client_session_id' => $client_session_id,
                'client_id' => $client->client_id,
                'active' => 1,
            ), array('%s'), array('%s', '%s', '%d'));
            if (false === $updated) {
                error_log('AHX WP SSO could not update client session activity: ' . $wpdb->last_error);
                return new WP_Error('ahx_sso_storage_error', __('Sitzungsaktivität konnte nicht aktualisiert werden.', 'ahx-wp-sso'), array('status' => 500));
            }
        }
        return rest_ensure_response(array('active' => 1 === (int) $activity->active && $host_session_valid));
    }

    private function client_callback() {
        $this->require_https();
        $state = isset($_GET['state']) ? sanitize_text_field(wp_unslash($_GET['state'])) : '';
        $code = isset($_GET['code']) ? sanitize_text_field(wp_unslash($_GET['code'])) : '';
        if (!preg_match('/^[a-f0-9]{64}$/', $state) || !preg_match('/^[a-f0-9]{64}$/', $code)) {
            $this->deny(__('Ungueltige SSO-Rueckgabe.', 'ahx-wp-sso'), 400);
        }

        $cookie_name = $this->state_cookie_name($state);
        $cookie_state = isset($_COOKIE[$cookie_name]) ? sanitize_text_field(wp_unslash($_COOKIE[$cookie_name])) : '';
        setcookie($cookie_name, '', array(
            'expires' => time() - HOUR_IN_SECONDS,
            'path' => defined('COOKIEPATH') && COOKIEPATH ? COOKIEPATH : '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ));
        if ('' === $cookie_state || !hash_equals($state, $cookie_state)) {
            $this->deny(__('Die SSO-Rueckgabe gehoert nicht zu diesem Browser oder ist abgelaufen.', 'ahx-wp-sso'), 403);
        }

        $flow = get_transient($this->flow_key($state));
        delete_transient($this->flow_key($state));
        if (!is_array($flow) || empty($flow['verifier'])) {
            $this->deny(__('Die SSO-Anfrage ist abgelaufen. Bitte erneut anmelden.', 'ahx-wp-sso'), 403);
        }
        $config = $this->config();
        $response = wp_remote_post($this->host_rest_url('token'), array(
            'timeout' => 10,
            'redirection' => 0,
            'sslverify' => true,
            'headers' => array('Content-Type' => 'application/json'),
            'body' => wp_json_encode(array(
                'client_id' => $config['client_id'],
                'client_secret' => $config['client_secret'],
                'code' => $code,
                'code_verifier' => $flow['verifier'],
            )),
        ));
        if (is_wp_error($response)) {
            error_log('AHX WP SSO token request failed: ' . $response->get_error_message());
            $this->deny(__('Der SSO-Host ist momentan nicht erreichbar.', 'ahx-wp-sso'), 503);
        }
        $response_code = wp_remote_retrieve_response_code($response);
        $response_body = wp_remote_retrieve_body($response);
        $body = json_decode($response_body, true);
        if (200 !== $response_code || !is_array($body)
            || empty($body['email']) || empty($body['session_id']) || empty($body['client_session_id'])) {
            $host_error_code = is_array($body) && isset($body['code'])
                ? sanitize_key((string) $body['code'])
                : 'invalid_response';
            $host_error_message = is_array($body) && isset($body['message'])
                ? sanitize_text_field((string) $body['message'])
                : 'Keine gueltige JSON-Antwort vom SSO-Host.';
            error_log(sprintf(
                'AHX WP SSO host rejected token exchange: HTTP %d, code=%s, message=%s',
                (int) $response_code,
                $host_error_code,
                $host_error_message
            ));
            $this->deny(__('Der SSO-Host hat die Anmeldung abgelehnt.', 'ahx-wp-sso'), 403);
        }
        $email = strtolower(trim(sanitize_email($body['email'])));
        $user = get_user_by('email', $email);
        if (!$user || strtolower(trim($user->user_email)) !== $email) {
            $this->deny(__('Auf dieser Site existiert kein lokales Benutzerkonto mit dieser E-Mail-Adresse. Wenden Sie sich an die Site-Administration.', 'ahx-wp-sso'), 403);
        }

        $expiration = apply_filters('auth_cookie_expiration', 2 * DAY_IN_SECONDS, $user->ID, false);
        $expires_at = time() + absint($expiration);
        $manager = WP_Session_Tokens::get_instance($user->ID);
        $token = $manager->create($expires_at);
        $registration = $this->session_request($body['session_id'], 'register', $body['client_session_id'], $expires_at);
        if (is_wp_error($registration) || empty($registration['active'])
            || !$this->store_client_session($user->ID, $token, $body['session_id'], $body['client_session_id'])) {
            $manager->destroy($token);
            if (is_wp_error($registration)) {
                error_log('AHX WP SSO could not register the client session expiration: ' . $registration->get_error_message());
            }
            $this->deny(__('Die lokale SSO-Sitzung konnte nicht gespeichert werden.', 'ahx-wp-sso'), 500);
        }
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, false, is_ssl(), $token);
        do_action('wp_login', $user->user_login, $user);
        wp_safe_redirect(wp_validate_redirect($flow['redirect'], home_url('/')));
        exit;
    }

    public function block_local_client_login($user, $username, $password) {
        if ('client' === $this->config()['mode'] && $user instanceof WP_User) {
            if (!$this->is_host_available() && $this->is_break_glass_user($user->ID)) {
                return $user;
            }
            return new WP_Error('ahx_sso_required', __('Bitte melden Sie sich ueber den zentralen SSO-Host an. Lokale Notfallanmeldungen sind nur fuer freigegebene Konten bei Nichterreichbarkeit des Hosts erlaubt.', 'ahx-wp-sso'));
        }
        return $user;
    }

    public function record_break_glass_cookie($auth_cookie, $expire, $expiration, $user_id, $scheme, $token) {
        if ('client' !== $this->config()['mode']
            || !$this->is_break_glass_user($user_id) || $this->is_host_available()) {
            return;
        }
        if ('' === $token || !$this->store_client_session($user_id, $token, '', '')) {
            $this->deny(__('Die lokale Notfallsitzung konnte nicht sicher gespeichert werden. Bitte die Anmeldung erneut versuchen.', 'ahx-wp-sso'), 500);
        }
    }

    public function break_glass_login_message($message) {
        if ('client' === $this->config()['mode'] && !$this->is_host_available()) {
            $message .= '<p class="message">' . esc_html__('Der SSO-Host ist nicht erreichbar. Nur zuvor freigegebene lokale Notfallkonten koennen sich anmelden.', 'ahx-wp-sso') . '</p>';
        }
        return $message;
    }

    public function client_login_message($message) {
        $context = $this->get_client_login_context();
        if (!$context) {
            return $message;
        }

        $branding = $this->get_client_branding($context['client']->client_id);
        $display_name = '' !== $branding['display_name']
            ? $branding['display_name']
            : $context['client']->client_name;
        return '<p class="message ahx-sso-client-message">' . esc_html(sprintf(
            __('Melde dich mit deinem zentralen Konto an, um zu %s zu gelangen.', 'ahx-wp-sso'),
            $display_name
        )) . '</p>' . $message;
    }

    public function client_login_title($login_title, $title = '', $action = '') {
        $context = $this->get_client_login_context();
        if (!$context) {
            return $login_title;
        }
        $branding = $this->get_client_branding($context['client']->client_id);
        $display_name = '' !== $branding['display_name'] ? $branding['display_name'] : $context['client']->client_name;
        return sprintf(__('Anmelden bei %s', 'ahx-wp-sso'), $display_name);
    }

    public function client_login_header_url($url) {
        $context = $this->get_client_login_context();
        if (!$context) {
            return $url;
        }
        $parts = wp_parse_url($context['client']->redirect_uri);
        if (!$parts || empty($parts['scheme']) || empty($parts['host'])) {
            return $url;
        }
        $port = isset($parts['port']) ? ':' . absint($parts['port']) : '';
        return strtolower($parts['scheme']) . '://' . $parts['host'] . $port . '/';
    }

    public function client_login_header_text($text) {
        $context = $this->get_client_login_context();
        if (!$context) {
            return $text;
        }
        $branding = $this->get_client_branding($context['client']->client_id);
        return '' !== $branding['display_name'] ? $branding['display_name'] : $context['client']->client_name;
    }

    public function client_login_styles() {
        $context = $this->get_client_login_context();
        if (!$context) {
            return;
        }

        $branding = $this->get_client_branding($context['client']->client_id);
        ?>
        <style>
            body.login { --ahx-sso-accent: <?php echo esc_html($branding['accent_color']); ?>; }
            body.login h1 a {
                <?php if ('' !== $branding['logo_url']) : ?>
                    background-image: url(<?php echo wp_json_encode(esc_url($branding['logo_url'])); ?>);
                    background-size: contain;
                    width: 100%;
                <?php endif; ?>
            }
            body.login #login { width: min(360px, calc(100% - 32px)); }
            body.login .button-primary { background: var(--ahx-sso-accent); border-color: var(--ahx-sso-accent); }
            body.login .button-primary:hover, body.login .button-primary:focus { filter: brightness(.92); background: var(--ahx-sso-accent); border-color: var(--ahx-sso-accent); }
            body.login input:focus { border-color: var(--ahx-sso-accent); box-shadow: 0 0 0 1px var(--ahx-sso-accent); }
            body.login .ahx-sso-client-message { border-left-color: var(--ahx-sso-accent); }
        </style>
        <?php
    }

    private function get_client_login_context() {
        if ('host' !== $this->config()['mode']) {
            return false;
        }

        $params = wp_unslash($_GET);
        if (
            isset($params['redirect_to'])
            && is_string($params['redirect_to'])
            && false !== strpos($params['redirect_to'], 'ahx_wp_sso=authorize')
        ) {
            $redirect_parts = wp_parse_url($params['redirect_to']);
            if (is_array($redirect_parts) && isset($redirect_parts['query'])) {
                parse_str($redirect_parts['query'], $redirect_params);
                $params = $redirect_params;
            }
        }

        if (!isset($params[self::ACTION]) || 'authorize' !== sanitize_key((string) $params[self::ACTION])) {
            return false;
        }
        $client_id = isset($params['client_id']) ? sanitize_text_field((string) $params['client_id']) : '';
        $redirect = isset($params['redirect_uri']) ? esc_url_raw((string) $params['redirect_uri']) : '';
        $state = isset($params['state']) ? sanitize_text_field((string) $params['state']) : '';
        $challenge = isset($params['code_challenge']) ? sanitize_text_field((string) $params['code_challenge']) : '';
        $client = $this->get_client($client_id);
        if (
            !$client
            || !$this->same_url($client->redirect_uri, $redirect)
            || !preg_match('/^[a-f0-9]{64}$/', $state)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/', $challenge)
        ) {
            return false;
        }

        return array('client' => $client);
    }

    public function validate_client_session() {
        if ('client' !== $this->config()['mode']) {
            return;
        }
        if (!is_user_logged_in()) {
            return;
        }
        $token = wp_get_session_token();
        if ('' === $token) {
            return;
        }
        $record = $this->get_client_session($token);
        if (!$record) {
            $this->force_logout(__('Diese Anmeldung wurde nicht ueber den SSO-Host erstellt.', 'ahx-wp-sso'));
        }
        if ('' === $record->session_id) {
            if ($this->is_host_available()) {
                $this->force_logout(__('Der SSO-Host ist wieder erreichbar. Bitte melden Sie sich jetzt ueber den zentralen Host an.', 'ahx-wp-sso'));
            }
            return;
        }

        $cache_key = 'ahx_sso_active_' . hash('sha256', $record->client_session_id);
        $active = get_transient($cache_key);
        if (false === $active) {
            $response = $this->session_request($record->session_id, 'check', $record->client_session_id);
            if (is_wp_error($response)) {
                error_log('AHX WP SSO session validation failed: ' . $response->get_error_message());
                $this->force_logout(__('Der SSO-Host kann die Sitzung derzeit nicht bestaetigen. Bitte spaeter erneut anmelden.', 'ahx-wp-sso'));
            }
            $active = !empty($response['active']) ? 1 : 0;
            set_transient($cache_key, $active, self::SESSION_CACHE_LIFETIME);
        }
        if (1 !== (int) $active) {
            $this->force_logout(__('Diese SSO-Sitzung wurde beendet. Bitte erneut anmelden.', 'ahx-wp-sso'));
        }
    }

    public function add_logout_menu($admin_bar) {
        if (!is_user_logged_in()) {
            return;
        }
        foreach (array(
            'local' => __('Nur diese Site abmelden', 'ahx-wp-sso'),
            'sites' => __('Alle Sites abmelden', 'ahx-wp-sso'),
            'devices' => __('Alle Geraete abmelden', 'ahx-wp-sso'),
        ) as $mode => $title) {
            $admin_bar->add_node(array(
                'id' => 'ahx-wp-sso-logout-' . $mode,
                'title' => esc_html($title),
                'href' => $this->logout_url($mode),
            ));
        }
    }

    private function logout_url($mode) {
        return wp_nonce_url(add_query_arg(array(
            'action' => 'logout',
            self::ACTION => 'logout_' . $mode,
            'redirect_to' => home_url('/'),
        ), site_url('wp-login.php', 'login')), 'ahx_wp_sso_logout_' . $mode);
    }

    private function handle_logout($action) {
        if ('' === $action) {
            check_admin_referer('log-out');
            $mode = 'sites';
        } elseif (0 === strpos($action, 'logout_')) {
            $mode = substr($action, 7);
            if (!in_array($mode, array('local', 'sites', 'devices'), true)) {
                return;
            }
            $nonce = isset($_REQUEST['_wpnonce']) ? sanitize_text_field(wp_unslash($_REQUEST['_wpnonce'])) : '';
            if (!wp_verify_nonce($nonce, 'ahx_wp_sso_logout_' . $mode)) {
                $this->deny(__('Ungueltige Abmeldeanfrage.', 'ahx-wp-sso'), 403);
            }
        } else {
            return;
        }

        if ('off' !== $this->config()['mode']) {
            $this->require_https();
        }

        $user_id = get_current_user_id();
        if ($user_id) {
            $current_token = wp_get_session_token();
            if ('client' === $this->config()['mode']) {
                $record = $this->get_client_session($current_token);
                if ($record && '' !== $record->session_id) {
                    if ('local' !== $mode) {
                        $operation = 'devices' === $mode ? 'revoke_all' : 'revoke';
                        $response = $this->session_request($record->session_id, $operation, $record->client_session_id);
                        if (is_wp_error($response) || (isset($response['error']))) {
                            error_log('AHX WP SSO remote logout failed.');
                            $this->deny(__('Der SSO-Host konnte die Abmeldung nicht bestaetigen. Bitte erneut versuchen.', 'ahx-wp-sso'), 503);
                        }
                    } else {
                        $response = $this->session_request($record->session_id, 'revoke_local', $record->client_session_id);
                        if (is_wp_error($response)) {
                            error_log('AHX WP SSO could not report local logout: ' . $response->get_error_message());
                        }
                    }
                    delete_transient('ahx_sso_active_' . hash('sha256', $record->client_session_id));
                } elseif ('devices' === $mode) {
                    WP_Session_Tokens::get_instance($user_id)->destroy_all();
                }
            } elseif ('host' === $this->config()['mode'] && 'local' !== $mode) {
                $this->revoke_host_sessions($user_id, $mode);
            } elseif ('devices' === $mode) {
                WP_Session_Tokens::get_instance($user_id)->destroy_all();
            } elseif ('local' === $mode || 'sites' === $mode) {
                WP_Session_Tokens::get_instance($user_id)->destroy($current_token);
            }
            WP_Session_Tokens::get_instance($user_id)->destroy($current_token);
            $this->delete_client_session($current_token);
        }

        $user = get_userdata($user_id);
        wp_clear_auth_cookie();
        wp_set_current_user(0);
        if ($user) {
            do_action('wp_logout', $user_id);
        }
        $redirect = isset($_REQUEST['redirect_to']) ? wp_unslash($_REQUEST['redirect_to']) : home_url('/');
        wp_safe_redirect(wp_validate_redirect($redirect, home_url('/')));
        exit;
    }

    private function ensure_host_session($user_id) {
        $host_token = wp_get_session_token();
        if ('' === $host_token) {
            return false;
        }
        $token_hash = hash('sha256', $host_token);
        global $wpdb;
        $table = $this->table('host_sessions');
        $existing = $wpdb->get_row($wpdb->prepare("SELECT session_id, active FROM $table WHERE user_id = %d AND host_token_hash = %s", $user_id, $token_hash));
        if (!empty($wpdb->last_error)) {
            error_log('AHX WP SSO could not find host session: ' . $wpdb->last_error);
            return false;
        }
        if ($existing) {
            return 1 === (int) $existing->active ? $existing->session_id : false;
        }
        $sid = bin2hex(random_bytes(32));
        $inserted = $wpdb->insert($table, array(
            'session_id' => $sid,
            'user_id' => $user_id,
            'host_token_hash' => $token_hash,
            'active' => 1,
            'created_at' => gmdate('Y-m-d H:i:s'),
        ), array('%s', '%d', '%s', '%d', '%s'));
        if (false === $inserted) {
            $existing = $wpdb->get_row($wpdb->prepare("SELECT session_id, active FROM $table WHERE user_id = %d AND host_token_hash = %s", $user_id, $token_hash));
            if ($existing && 1 === (int) $existing->active) {
                return $existing->session_id;
            }
            error_log('AHX WP SSO could not create host session: ' . $wpdb->last_error);
            return false;
        }
        return $sid;
    }

    private function revoke_host_sessions($user_id, $mode) {
        global $wpdb;
        $table = $this->table('host_sessions');
        $where = array('user_id' => absint($user_id), 'active' => 1);
        $formats = array('%d', '%d');
        if ('sites' === $mode) {
            $host_token = wp_get_session_token();
            if ('' === $host_token) {
                $this->deny(__('Die aktuelle SSO-Sitzung konnte nicht ermittelt werden.', 'ahx-wp-sso'), 403);
            }
            $where['host_token_hash'] = hash('sha256', $host_token);
            $formats[] = '%s';
        }
        $updated = $wpdb->update($table, array(
            'active' => 0,
            'revoked_at' => gmdate('Y-m-d H:i:s'),
        ), $where, array('%d', '%s'), $formats);
        if (false === $updated) {
            error_log('AHX WP SSO could not revoke host sessions: ' . $wpdb->last_error);
            $this->deny(__('Die SSO-Sitzungen konnten nicht abgemeldet werden.', 'ahx-wp-sso'), 500);
        }
        if ('devices' === $mode) {
            WP_Session_Tokens::get_instance(absint($user_id))->destroy_all();
        } else {
            WP_Session_Tokens::get_instance(absint($user_id))->destroy(wp_get_session_token());
        }
    }

    private function store_client_session($user_id, $token, $session_id, $client_session_id) {
        global $wpdb;
        $table = $this->table('client_sessions');
        $inserted = $wpdb->insert($table, array(
            'token_hash' => hash('sha256', $token),
            'user_id' => $user_id,
            'session_id' => $session_id,
            'client_session_id' => $client_session_id,
            'created_at' => gmdate('Y-m-d H:i:s'),
        ), array('%s', '%d', '%s', '%s', '%s'));
        if (false === $inserted) {
            error_log('AHX WP SSO could not store client session: ' . $wpdb->last_error);
            return false;
        }
        return true;
    }

    private function get_client_session($token) {
        if ('' === $token) {
            return false;
        }
        global $wpdb;
        $table = $this->table('client_sessions');
        $row = $wpdb->get_row($wpdb->prepare("SELECT user_id, session_id, client_session_id FROM $table WHERE token_hash = %s", hash('sha256', $token)));
        if (!empty($wpdb->last_error)) {
            error_log('AHX WP SSO could not look up client session: ' . $wpdb->last_error);
            return false;
        }
        return $row;
    }

    private function session_request($session_id, $operation, $client_session_id, $expires_at = 0) {
        $config = $this->config();
        $response = wp_remote_post($this->host_rest_url('session'), array(
            'timeout' => 5,
            'redirection' => 0,
            'sslverify' => true,
            'headers' => array('Content-Type' => 'application/json'),
            'body' => wp_json_encode(array(
                'client_id' => $config['client_id'],
                'client_secret' => $config['client_secret'],
                'session_id' => $session_id,
                'client_session_id' => $client_session_id,
                'operation' => $operation,
                'expires_at' => absint($expires_at),
            )),
        ));
        if (is_wp_error($response)) {
            return $response;
        }
        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (200 !== wp_remote_retrieve_response_code($response) || !is_array($body)) {
            return new WP_Error('ahx_sso_remote_error', __('Der SSO-Host hat die Anfrage abgelehnt.', 'ahx-wp-sso'));
        }
        return $body;
    }

    private function is_host_available() {
        if (null !== $this->host_availability) {
            return $this->host_availability;
        }
        $config = $this->config();
        if (empty($config['host_url'])) {
            $this->host_availability = false;
            return false;
        }
        $cache_key = 'ahx_sso_host_available_' . hash('sha256', $config['host_url']);
        $cached = get_transient($cache_key);
        if (false !== $cached) {
            $this->host_availability = 1 === (int) $cached;
            return $this->host_availability;
        }

        $response = wp_remote_get($this->host_rest_url('health'), array(
            'timeout' => 3,
            'redirection' => 0,
            'sslverify' => true,
        ));
        $available = false;
        if (is_wp_error($response)) {
            error_log('AHX WP SSO host health check failed: ' . $response->get_error_message());
        } else {
            $status = (int) wp_remote_retrieve_response_code($response);
            $available = $status >= 100 && $status < 500;
        }
        $this->host_availability = $available;
        set_transient($cache_key, $available ? 1 : 0, $available ? self::HOST_CHECK_CACHE_LIFETIME : 2);
        return $available;
    }

    private function is_break_glass_user($user_id) {
        $allowed_ids = isset($this->config()['break_glass_user_ids']) && is_array($this->config()['break_glass_user_ids'])
            ? array_map('absint', $this->config()['break_glass_user_ids'])
            : array();
        return in_array(absint($user_id), $allowed_ids, true);
    }

    private function authenticate_client($request) {
        $client_id = sanitize_text_field((string) $request->get_param('client_id'));
        $secret = (string) $request->get_param('client_secret');
        if (!preg_match('/^[a-f0-9]{64}$/', $client_id) || !preg_match('/^[a-f0-9]{64}$/', $secret)) {
            return new WP_Error('ahx_sso_client_auth', __('Client-Authentifizierung fehlgeschlagen.', 'ahx-wp-sso'), array('status' => 401));
        }
        $client = $this->get_client($client_id);
        if (!$client || !hash_equals($client->secret_hash, hash('sha256', $secret))) {
            return new WP_Error('ahx_sso_client_auth', __('Client-Authentifizierung fehlgeschlagen.', 'ahx-wp-sso'), array('status' => 401));
        }
        return $client;
    }

    private function get_client($client_id) {
        if (!preg_match('/^[a-f0-9]{64}$/', $client_id)) {
            return false;
        }
        global $wpdb;
        $client = $wpdb->get_row($wpdb->prepare("SELECT client_id, secret_hash, redirect_uri FROM " . $this->table('clients') . " WHERE client_id = %s", $client_id));
        if (!empty($wpdb->last_error)) {
            error_log('AHX WP SSO could not look up client: ' . $wpdb->last_error);
            return false;
        }
        return $client;
    }

    private function same_url($first, $second) {
        return is_string($first) && is_string($second) && hash_equals(untrailingslashit($first), untrailingslashit($second));
    }

    private function flow_key($state) {
        return 'ahx_wp_sso_flow_' . hash('sha256', $state);
    }

    private function state_cookie_name($state) {
        return 'ahx_wp_sso_state_' . substr(hash('sha256', $state), 0, 32);
    }

    private function pkce_challenge($verifier) {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private function callback_url() {
        return set_url_scheme(add_query_arg(self::ACTION, 'callback', site_url('wp-login.php', 'login')), 'https');
    }

    private function host_rest_url($route) {
        $config = $this->config();
        return add_query_arg(
            'rest_route',
            '/' . self::REST_NAMESPACE . '/' . sanitize_key($route),
            trailingslashit($config['host_url'])
        );
    }

    private function table($suffix) {
        global $wpdb;
        return $wpdb->base_prefix . 'ahx_wp_sso_' . $suffix;
    }

    private function config() {
        $config = get_option('ahx_wp_sso_config', array());
        if (!is_array($config)) {
            $config = array();
        }
        $config['mode'] = isset($config['mode']) ? $config['mode'] : 'off';
        return $config;
    }

    private function is_network_active() {
        $active = get_site_option('active_sitewide_plugins', array());
        return isset($active[plugin_basename(AHX_WP_SSO_FILE)]);
    }

    private function is_https_request() {
        return is_ssl();
    }

    private function require_https() {
        if (!$this->is_https_request()) {
            $this->deny(__('Der SSO-Ablauf erfordert HTTPS auf Host und Client-Site.', 'ahx-wp-sso'), 403);
        }
    }

    private function force_logout($message) {
        $user_id = get_current_user_id();
        $token = wp_get_session_token();
        if ($user_id && '' !== $token) {
            WP_Session_Tokens::get_instance($user_id)->destroy($token);
            $this->delete_client_session($token);
        }
        wp_clear_auth_cookie();
        wp_set_current_user(0);
        $this->deny($message, 403);
    }

    private function delete_client_session($token) {
        if ('' === $token) {
            return;
        }
        global $wpdb;
        $deleted = $wpdb->delete($this->table('client_sessions'), array(
            'token_hash' => hash('sha256', $token),
        ), array('%s'));
        if (false === $deleted) {
            error_log('AHX WP SSO could not delete local session mapping: ' . $wpdb->last_error);
        }
    }

    private function deny($message, $status) {
        wp_die(esc_html($message), esc_html__('AHX WP SSO', 'ahx-wp-sso'), array('response' => absint($status)));
    }
}
