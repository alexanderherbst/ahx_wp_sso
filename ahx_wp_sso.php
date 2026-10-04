<?php
/*
Plugin Name: AHX WP SSO
Description: Zentraler Anmeldehost fuer WordPress-Einzelinstallationen und Multisite.
Version: v0.2.3
Requires PHP: 7.3
Author: AHX
*/

if (!defined('ABSPATH')) {
    exit;
}

define('AHX_WP_SSO_VERSION', 'v0.2.3');
define('AHX_WP_SSO_FILE', __FILE__);
define('AHX_WP_SSO_DIR', plugin_dir_path(__FILE__));

require_once AHX_WP_SSO_DIR . 'includes/class-ahx-wp-sso.php';

register_activation_hook(__FILE__, array('AHX_WP_SSO', 'activate'));
AHX_WP_SSO::instance();
