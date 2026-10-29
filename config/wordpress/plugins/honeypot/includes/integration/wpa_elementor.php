<?php
if ( ! defined( 'ABSPATH' ) ) exit; 

if (!function_exists('wpae_get_blocked_integrations') || !in_array('elementor', wpae_get_blocked_integrations())) :

	function wpa_elementor_extra_validation( $record, $ajax_handler ) { 
	   	if (wpa_check_is_spam($_POST)){
	   		$all_fields = $record->get( 'fields' );
			$firstField = array_key_first($all_fields);
			do_action('wpa_handle_spammers','elementor', $_POST);
			$ajax_handler->add_error($all_fields[$firstField]['id'], $GLOBALS['wpa_error_message']);
		}
	};
	add_action( 'elementor_pro/forms/validation', 'wpa_elementor_extra_validation', 10, 2 );

endif;