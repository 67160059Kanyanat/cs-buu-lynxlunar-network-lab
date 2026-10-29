<?php
if ( ! defined( 'ABSPATH' ) ) exit; 

if (!function_exists('wpae_get_blocked_integrations') || !in_array('calderaforms', wpae_get_blocked_integrations())) :
	function wpa_calderaforms_extra_validation(  ) { 
	   	if (wpa_check_is_spam($_POST)){
			do_action('wpa_handle_spammers','calderaforms', $_POST);
			die($GLOBALS['wpa_error_message']);
		}
	};
	add_action( 'caldera_forms_pre_load_processors', 'wpa_calderaforms_extra_validation', 10, 0 );
endif;