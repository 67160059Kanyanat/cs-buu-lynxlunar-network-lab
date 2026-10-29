<?php 
if ( ! defined( 'ABSPATH' ) ) exit; 

$wpae_nonce = '&_wpnonce='.wp_create_nonce( 'wpae_action_nonce' ); 

if ( isset( $_GET['action'] ) && isset( $_GET['_wpnonce'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'wpae_action_nonce' ) ) {    
    switch ($_GET['action']) {
        case 'resetstats':
                if (function_exists('wpae_reset_stats')){
                    wpae_reset_stats();
                    $actionReturn = array('status' => 'ok','body'=>'Stats Reset' );
                }
            break;
    }
}
$currentStats = json_decode(get_option('wpa_stats'), true); 
?>

<?php if (isset($actionReturn)):?>
    <div class="updated <?php echo $actionReturn['status']; ?>" id="message"><p><?php echo $actionReturn['body']; ?></p></div>
<?php endif; ?>

<br/>

<?php if (function_exists('wpae_reset_stats')){ ?>
    <div class="wpae_bulk_actions">
        <a href="admin.php?page=wp-armour&tab=stats&action=resetstats<?php echo $wpae_nonce ?>" onclick="return confirm('Are you sure? This action is irreversible.')">Reset Stats</a>
    </div>
<?php } ?>

<table class="wp-list-table widefat fixed bookmarks">
    <?php
    /*
    <thead>
    <tr>
        <th colspan="5"><strong>Quick Stats</strong></th>
    </tr>
    </thead>
    */ ?>
    <thead>
        <tr>
            <th><strong>Source</strong></th>
            <th><strong>Today</strong></th>
            <th><strong>This Week</strong></th>
            <th><strong>This Month</strong></th>
            <th><strong>All Time</strong></th>        
        </tr>
    <thead>
     <tbody>
        <?php         
        if (!empty($currentStats)){
            foreach ($currentStats as $source=>$statData): ?>
                <tr>
                    <td><strong><?php echo ucfirst($source); ?></strong></td>
                    <td><?php echo @wpa_check_date($statData['today']['date'],'today')?$statData['today']['count']:'0'; ?></td>
                    <td><?php echo @wpa_check_date($statData['week']['date'],'week')?$statData['week']['count']:'0'; ?></td>
                    <td><?php echo @wpa_check_date($statData['month']['date'],'month')?$statData['month']['count']:'0'; ?></td>
                    <td><?php echo $statData['all_time']; ?></td>        
                </tr>
            <?php endforeach;
        } else { ?>
            <tr><td colspan="5">No Record Found</td></tr>
        <?php } ?>

    </tbody>
</table><br/>
<br/>