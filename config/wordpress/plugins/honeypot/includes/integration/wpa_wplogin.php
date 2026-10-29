<?php
if ( ! defined( 'ABSPATH' ) ) exit;

if (!function_exists('wpae_get_blocked_integrations') || !in_array('wp_login_form', wpae_get_blocked_integrations())) :	

	function wpa_wplogin_add_initiator_field() {
	    echo '<input type="hidden" id="wpa_initiator" class="wpa_initiator" name="wpa_initiator" value="" />';
	}

	add_action('lostpassword_form', 'wpa_wplogin_add_initiator_field');
	add_action('woocommerce_lostpassword_form', 'wpa_wplogin_add_initiator_field');
	 
	add_action( 'login_form', 'wpa_wplogin_add_initiator_field' );
	add_action( 'woocommerce_login_form', 'wpa_wplogin_add_initiator_field' ); // FIX FOR WOOCOMMERCE LOGIN.


	function wpae_wplogin_extra_validation( $user, $username, $password ) {
	    if ( ! empty( $_POST ) ) {
		    if (wpa_check_is_spam($_POST)){
		    	$postData = $_POST;
				$postData['pwd']	= '**removed**';
				do_action('wpa_handle_spammers','wplogin', $postData);
				return new WP_Error( 'error', $GLOBALS['wpa_error_message']);
			}
		}
		//return $user;
	}
	add_filter( 'authenticate', 'wpae_wplogin_extra_validation', 10, 3 );


	function wpae_lostpassword_extra_validation( $errors ) {
		if ( is_admin() ) { return; }

	    if (wpa_check_is_spam($_POST)){
				do_action('wpa_handle_spammers','losspassword', $_POST);
				$errors->add( 'user_login', __($GLOBALS['wpa_error_message']) );
		}
	}
	add_action( 'lostpassword_post', 'wpae_lostpassword_extra_validation' );

endif;