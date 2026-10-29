<?php
if ( ! defined( 'ABSPATH' ) ) exit; 
/* BB PRESS */

if (!function_exists('wpae_get_blocked_integrations') || !in_array('bbpress', wpae_get_blocked_integrations())) :
	add_action(	'bbp_new_topic_pre_extras','wpa_bbp_extra_validation');
	add_action(	'bbp_new_reply_pre_extras','wpa_bbp_extra_validation');

	function wpa_bbp_extra_validation(){
		if (wpa_check_is_spam($_POST)){
			do_action('wpa_handle_spammers','bbpress', $_POST);
			bbp_add_error( 'bbp_extra_email', __( $GLOBALS['wpa_error_message'], 'bbpress' ) );
		}
	}

endif;