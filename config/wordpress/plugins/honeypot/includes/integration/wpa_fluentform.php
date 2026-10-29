<?php
if ( ! defined( 'ABSPATH' ) ) exit; 

if (!function_exists('wpae_get_blocked_integrations') || !in_array('fluentform', wpae_get_blocked_integrations())) :

	function wpa_fluent_form_extra_validation($insertData, $data, $form) { 
	   if (wpa_check_is_spam($data)){
	   		do_action('wpa_handle_spammers','fluent_forms', $data);
				//die($GLOBALS['wpa_error_message']);
				wp_send_json_error(['errors' => $GLOBALS['wpa_error_message']]);
				wp_die();
		}
	};
	//add_action( 'fluentform_before_insert_submission', 'wpa_fluent_form_extra_validation', 10, 3 );
	add_action( 'fluentform/before_insert_submission', 'wpa_fluent_form_extra_validation', 10, 3 );

endif;