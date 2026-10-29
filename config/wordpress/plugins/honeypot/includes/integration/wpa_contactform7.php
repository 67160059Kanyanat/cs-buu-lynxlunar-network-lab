<?php
if ( ! defined( 'ABSPATH' ) ) exit; 

if (!function_exists('wpae_get_blocked_integrations') || !in_array('contactform7', wpae_get_blocked_integrations())) :

	add_filter( 'wpcf7_validate', 'wpa_contactform7_extra_validation', 10, 2 );

	function wpa_contactform7_extra_validation($result, $tags){
		if ( empty( $result->get_invalid_fields() ) ) { // only check spam if validation OK (Imp for Level 2)
		 	if (wpa_check_is_spam($_POST)){
				do_action('wpa_handle_spammers','contactform7', $_POST);
				$result->invalidate('', $GLOBALS['wpa_error_message']);
			}
		}	
		return $result;
	}

endif;