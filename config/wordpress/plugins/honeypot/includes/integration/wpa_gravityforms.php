<?php
if ( ! defined( 'ABSPATH' ) ) exit; 

if (!function_exists('wpae_get_blocked_integrations') || !in_array('gravityforms', wpae_get_blocked_integrations())) :

	add_action( 'gform_validation', 'wpa_gravityforms_extra_validation');

	function wpa_gravityforms_extra_validation($validation_result ){
		if (wpa_check_is_spam($_POST)){
			$form = $validation_result['form'];
			do_action('wpa_handle_spammers','gravityforms', $_POST);
			$validation_result['is_valid'] = false;
			$form['fields'][0]->failed_validation = true;
			$form['fields'][0]->validation_message = $GLOBALS['wpa_error_message'];
			$validation_result['form'] = $form;
		}
		return $validation_result;
	}
endif;