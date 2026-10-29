<?php
if ( ! defined( 'ABSPATH' ) ) exit; 

if (!function_exists('wpae_get_blocked_integrations') || !in_array('formidable', wpae_get_blocked_integrations())) :

	add_filter( 'frm_validate_entry', 'wpa_formidable_extra_validation', 10, 2 );

	function wpa_formidable_extra_validation($errors, $values){
		if (wpa_check_is_spam($_POST)){
			do_action('wpa_handle_spammers','formidable', $_POST);
			$errors['my_error'] = $GLOBALS['wpa_error_message'];
		}
		return $errors;
	}

endif;