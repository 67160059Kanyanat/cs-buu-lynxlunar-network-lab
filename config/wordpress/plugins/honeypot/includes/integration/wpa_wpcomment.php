<?php
if ( ! defined( 'ABSPATH' ) ) exit; 
// WP Comments // TESTED WITH LEVEL2. Working FINE

if (!function_exists('wpae_get_blocked_integrations') || !in_array('wpcomment', wpae_get_blocked_integrations())) :

    add_filter( 'preprocess_comment', 'wpa_wpcomment_extra_validation' );

    function wpa_wpcomment_extra_validation( $commentdata ) {
        if (wpa_check_is_spam($_POST)){
    		do_action('wpa_handle_spammers','wpcomment', $_POST);
            wp_die( __( $GLOBALS['wpa_error_message'] ) );
        }
        return $commentdata;
    }

endif;