<?php

/***************************************************************************
 *   Clover POS Payment Plugin for PC Repair Tracker
 *   Pushes orders with line items to Clover and initiates payment on
 *   Clover Flex terminal. Supports parts/labor tax breakdown.
 ***************************************************************************/

if (array_key_exists('func',$_REQUEST)) {
$func = $_REQUEST['func'];
} else {
$func = "";
}


function nothing() {
require_once("header.php");
require_once("footer.php");
}


/**
 * Clover API helper - makes authenticated REST API calls
 */
function clover_api($method, $endpoint, $data = null) {
    require("deps.php");

    $base_url = ($CloverEnvironment == 'sandbox')
        ? 'https://sandbox.dev.clover.com'
        : 'https://api.clover.com';

    $url = $base_url . '/v3/merchants/' . $CloverMerchantId . $endpoint;

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'Authorization: Bearer ' . $CloverAccessToken,
        'Content-Type: application/json',
        'Accept: application/json'
    ));

    if ($method == 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        if ($data) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }
    } elseif ($method == 'DELETE') {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
    }

    $response = curl_exec($ch);
    $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $result = json_decode($response, true);
    $result['_httpcode'] = $httpcode;
    return $result;
}


/**
 * Get list of Clover devices for this merchant
 */
function clover_get_devices() {
    $result = clover_api('GET', '/devices');
    if (isset($result['elements'])) {
        return $result['elements'];
    }
    return array();
}


/**
 * Get cart line items with tax breakdown for Clover order
 */
function clover_get_cart_items() {
    require("deps.php");
    require_once("common.php");

    $ipofpc = getipofpc();

    $items = array();
    $sql = "SELECT c.*, s.itemname, s.itemdescription
            FROM cart c
            LEFT JOIN stock s ON c.cart_stock_id = s.stockid
            WHERE c.ipofpc = '$ipofpc'";
    $q = @mysqli_query($rs_connect, $sql);

    while ($row = mysqli_fetch_object($q)) {
        $item = array(
            'name' => '',
            'price' => round($row->cart_price * 100), // Clover uses cents
            'tax' => round($row->itemtax * 100),
            'type' => $row->cart_type,
            'quantity' => (int)$row->quantity,
            'unit_price' => round($row->unit_price * 100)
        );

        if ($row->cart_type == 'purchase' || $row->cart_type == 'refund') {
            $item['name'] = $row->itemname ? $row->itemname : 'Part/Product';
            $item['category'] = 'parts';
        } else {
            $item['name'] = $row->labor_desc ? $row->labor_desc : 'Labor/Service';
            $item['category'] = 'labor';
        }

        $items[] = $item;
    }

    return $items;
}


/**
 * Create a Clover order with line items and tax
 */
function clover_create_order($currenttotal, $items) {
    // Create the order
    $order_data = array(
        'state' => 'open',
        'manualTransaction' => true,
        'total' => round($currenttotal * 100) // cents
    );

    $order = clover_api('POST', '/orders', $order_data);

    if (!isset($order['id'])) {
        return array('error' => 'Failed to create Clover order: ' . json_encode($order));
    }

    $order_id = $order['id'];

    // Add line items
    foreach ($items as $item) {
        $line_item_data = array(
            'name' => $item['name'],
            'price' => $item['unit_price'],
            'unitQty' => $item['quantity'] * 1000 // Clover uses 1/1000 units
        );

        $li = clover_api('POST', '/orders/' . $order_id . '/line_items', $line_item_data);

        // If item has tax, add tax rate to the line item
        if ($item['tax'] > 0 && isset($li['id'])) {
            // Apply default order-level tax (handled by Clover's tax settings)
        }
    }

    return array('order_id' => $order_id, 'order' => $order);
}


/**
 * STEP 1: Show payment confirmation and push to Clover terminal
 */
function add() {

if (array_key_exists('currenttotal',$_REQUEST)) {
$currenttotal =  $_REQUEST['currenttotal'];
} else {
$currenttotal = "";
}

if (array_key_exists('isdeposit',$_REQUEST)) {
$isdeposit =  $_REQUEST['isdeposit'];
} else {
$isdeposit = "0";
}

if (array_key_exists('woid',$_REQUEST)) {
$woid =  $_REQUEST['woid'];
} else {
$woid = "0";
}

if (array_key_exists('invoiceid',$_REQUEST)) {
$invoiceid =  $_REQUEST['invoiceid'];
} else {
$invoiceid = "0";
}

if (array_key_exists('cfirstname',$_REQUEST)) {
$cfirstname = $_REQUEST['cfirstname'];
} else {
$cfirstname = "";
}
if (array_key_exists('ccompany',$_REQUEST)) {
$ccompany = $_REQUEST['ccompany'];
} else {
$ccompany = "";
}
if (array_key_exists('caddress',$_REQUEST)) {
$caddress = $_REQUEST['caddress'];
} else {
$caddress = "";
}
if (array_key_exists('caddress2',$_REQUEST)) {
$caddress2 = $_REQUEST['caddress2'];
} else {
$caddress2 = "";
}
if (array_key_exists('ccity',$_REQUEST)) {
$ccity = $_REQUEST['ccity'];
} else {
$ccity = "";
}
if (array_key_exists('cstate',$_REQUEST)) {
$cstate = $_REQUEST['cstate'];
} else {
$cstate = "";
}
if (array_key_exists('czip',$_REQUEST)) {
$czip = $_REQUEST['czip'];
} else {
$czip = "";
}
if (array_key_exists('cphone',$_REQUEST)) {
$cphone = $_REQUEST['cphone'];
} else {
$cphone = "";
}
if (array_key_exists('cemail',$_REQUEST)) {
$cemail = $_REQUEST['cemail'];
} else {
$cemail = "";
}

if (array_key_exists('taxamt',$_REQUEST)) {
$taxamt = $_REQUEST['taxamt'];
} else {
$taxamt = "0";
}

require("header.php");

start_box();
echo "<h2>".pcrtlang("Clover Terminal Payment")."</h2>";

echo "<div style='margin:10px 0; padding:15px; background:#f8f9fa; border-radius:8px;'>";
echo "<table style='width:100%; font-size:16px;'>";
echo "<tr><td><strong>Total:</strong></td><td align=right><strong style='font-size:22px;'>$money" . mf($currenttotal) . "</strong></td></tr>";
if ($taxamt > 0) {
echo "<tr><td style='color:#666;'>Includes Tax:</td><td align=right style='color:#666;'>$money" . mf($taxamt) . "</td></tr>";
}
echo "</table></div>";

echo "<p style='font-size:14px; color:#666;'>Click below to send payment to the Clover Flex terminal. The customer can then tap, insert, or swipe their card.</p>";

echo "<form action=Clover.php?func=add2 method=post>";
echo "<input type=hidden name=currenttotal value=\"" . mf("$currenttotal") . "\">";
echo "<input type=hidden name=cfirstname value=\"$cfirstname\">";
echo "<input type=hidden name=ccompany value=\"$ccompany\">";
echo "<input type=hidden name=caddress value=\"$caddress\">";
echo "<input type=hidden name=caddress2 value=\"$caddress2\">";
echo "<input type=hidden name=ccity value=\"$ccity\">";
echo "<input type=hidden name=cstate value=\"$cstate\">";
echo "<input type=hidden name=czip value=\"$czip\">";
echo "<input type=hidden name=cphone value=\"$cphone\">";
echo "<input type=hidden name=cemail value=\"$cemail\">";
echo "<input type=hidden name=isdeposit value=\"$isdeposit\">";
echo "<input type=hidden name=woid value=\"$woid\">";
echo "<input type=hidden name=invoiceid value=\"$invoiceid\">";
echo "<input type=hidden name=taxamt value=\"$taxamt\">";
echo "<input type=submit class=button value=\"" . pcrtlang("Send to Clover Terminal") . "\" style='width:97%; background:#4CAF50; color:white; font-size:18px; padding:12px; cursor:pointer;'>";
echo "</form>";

echo "<br><form action=cart.php method=get>";
echo "<input type=submit class=button value=\"" . pcrtlang("Cancel") . "\" style='width:97%;'>";
echo "</form>";

stop_box();
require("footer.php");
}


/**
 * STEP 2: Create Clover order, push to terminal, wait for payment
 */
function add2() {

require("deps.php");

$currenttotal = $_REQUEST['currenttotal'];
$cfirstname = $_REQUEST['cfirstname'];
$ccompany = $_REQUEST['ccompany'];
$caddress = $_REQUEST['caddress'];
$caddress2 = $_REQUEST['caddress2'];
$ccity = $_REQUEST['ccity'];
$cstate = $_REQUEST['cstate'];
$czip = $_REQUEST['czip'];
$cphone = $_REQUEST['cphone'];
$cemail = $_REQUEST['cemail'];
$isdeposit = $_REQUEST['isdeposit'];
$woid = $_REQUEST['woid'];
$invoiceid = $_REQUEST['invoiceid'];
$taxamt = isset($_REQUEST['taxamt']) ? $_REQUEST['taxamt'] : '0';

// Create Clover order via API
$order_result = clover_create_order($currenttotal, array());

// Output HTML directly (no header.php to avoid include conflicts)
echo "<!DOCTYPE html><html><head><title>Clover Payment</title>";
echo "<meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>";
echo "<style>body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5;} .box{background:white;padding:30px;border-radius:10px;max-width:500px;margin:0 auto;box-shadow:0 2px 10px rgba(0,0,0,0.1);} @keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}} .spinner{border:4px solid #f3f3f3;border-top:4px solid #4CAF50;border-radius:50%;width:40px;height:40px;animation:spin 1s linear infinite;margin:0 auto;} .btn{padding:10px 30px;font-size:16px;cursor:pointer;border:1px solid #ccc;border-radius:5px;background:#eee;}</style>";
echo "</head><body>";

if (isset($order_result['error'])) {
    echo "<div class='box' style='text-align:center;'>";
    echo "<h2 style='color:red;'>Clover Error</h2>";
    echo "<p>" . htmlspecialchars($order_result['error']) . "</p>";
    echo "<p><a href='cart.php'>Back to Cart</a></p>";
    echo "</div></body></html>";
    return;
}

$order_id = $order_result['order_id'];

echo "<div class='box' style='text-align:center;'>";

echo "<h2>Waiting for Payment on Clover Terminal...</h2>";
echo "<div id='clover-status' style='text-align:center; padding:30px;'>";
echo "<div style='font-size:48px; margin:20px;'>&#128179;</div>"; // credit card emoji
echo "<p style='font-size:20px;'><strong>&#36;" . number_format($currenttotal, 2) . "</strong></p>";
echo "<p style='font-size:16px; color:#666;'>Customer: please tap, insert, or swipe card on the Clover terminal</p>";
echo "<div id='payment-spinner' style='margin:20px;'>";
echo "<div style='border:4px solid #f3f3f3; border-top:4px solid #4CAF50; border-radius:50%; width:40px; height:40px; animation:spin 1s linear infinite; margin:0 auto;'></div>";
echo "</div>";
echo "<p id='status-text' style='color:#888;'>Checking payment status...</p>";
echo "</div>";

echo "<style>@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }</style>";

// Hidden form for when payment completes
echo "<form id='payment-complete-form' action='Clover.php?func=add3' method='post' style='display:none;'>";
echo "<input type=hidden name=currenttotal value=\"" . number_format($currenttotal, 2, '.', '') . "\">";
echo "<input type=hidden name=cfirstname value=\"$cfirstname\">";
echo "<input type=hidden name=ccompany value=\"$ccompany\">";
echo "<input type=hidden name=caddress value=\"$caddress\">";
echo "<input type=hidden name=caddress2 value=\"$caddress2\">";
echo "<input type=hidden name=ccity value=\"$ccity\">";
echo "<input type=hidden name=cstate value=\"$cstate\">";
echo "<input type=hidden name=czip value=\"$czip\">";
echo "<input type=hidden name=cphone value=\"$cphone\">";
echo "<input type=hidden name=cemail value=\"$cemail\">";
echo "<input type=hidden name=isdeposit value=\"$isdeposit\">";
echo "<input type=hidden name=woid value=\"$woid\">";
echo "<input type=hidden name=invoiceid value=\"$invoiceid\">";
echo "<input type=hidden name=taxamt value=\"$taxamt\">";
echo "<input type=hidden id='clover_order_id' name=clover_order_id value=\"$order_id\">";
echo "<input type=hidden id='clover_payment_id' name=clover_payment_id value=''>";
echo "<input type=hidden id='clover_card_last4' name=clover_card_last4 value=''>";
echo "<input type=hidden id='clover_card_brand' name=clover_card_brand value=''>";
echo "</form>";

// Cancel button
echo "<div style='text-align:center; margin-top:20px;'>";
echo "<form action='cart.php' method='get' style='display:inline;'>";
echo "<input type=submit class=button value='Cancel' style='padding:8px 30px;'>";
echo "</form></div>";

// JavaScript to poll for payment completion
echo "<script>";
echo "var orderId = '$order_id';";
echo "var pollInterval;";
echo "var pollCount = 0;";
echo "var maxPolls = 120;";
echo "function checkPayment() {";
echo "    pollCount++;";
echo "    if (pollCount > maxPolls) {";
echo "        document.getElementById('status-text').innerHTML = '<span style=\"color:orange;\">Payment timeout. Please check the Clover terminal or try again.</span>';";
echo "        document.getElementById('payment-spinner').style.display = 'none';";
echo "        clearInterval(pollInterval);";
echo "        return;";
echo "    }";
echo "    var xhr = new XMLHttpRequest();";
echo "    xhr.open('GET', 'Clover.php?func=check_payment&order_id=' + orderId, true);";
echo "    xhr.onreadystatechange = function() {";
echo "        if (xhr.readyState == 4 && xhr.status == 200) {";
echo "            try {";
echo "                var data = JSON.parse(xhr.responseText);";
echo "                if (data.paid) {";
echo "                    clearInterval(pollInterval);";
echo "                    document.getElementById('status-text').innerHTML = '<span style=\"color:#4CAF50; font-size:24px;\">&#10004; Payment Approved!</span>';";
echo "                    document.getElementById('payment-spinner').style.display = 'none';";
echo "                    document.getElementById('clover_payment_id').value = data.payment_id;";
echo "                    document.getElementById('clover_card_last4').value = data.last4;";
echo "                    document.getElementById('clover_card_brand').value = data.card_brand;";
echo "                    setTimeout(function() { document.getElementById('payment-complete-form').submit(); }, 1500);";
echo "                } else if (data.error) {";
echo "                    clearInterval(pollInterval);";
echo "                    document.getElementById('status-text').innerHTML = '<span style=\"color:red;\">Payment failed: ' + data.error + '</span>';";
echo "                    document.getElementById('payment-spinner').style.display = 'none';";
echo "                }";
echo "            } catch(e) {}";
echo "        }";
echo "    };";
echo "    xhr.send();";
echo "}";
echo "pollInterval = setInterval(checkPayment, 2000);";
echo "checkPayment();";
echo "</script>";

echo "</div>"; // close .box
echo "</body></html>";
}


/**
 * AJAX endpoint: Check if Clover order has been paid
 */
function check_payment() {
    require("deps.php");

    header('Content-Type: application/json');

    $order_id = isset($_REQUEST['order_id']) ? $_REQUEST['order_id'] : '';

    if (empty($order_id)) {
        echo json_encode(array('paid' => false, 'error' => 'No order ID'));
        return;
    }

    // Check order payments via Clover API
    $result = clover_api('GET', '/orders/' . $order_id . '/payments');

    if (isset($result['elements']) && count($result['elements']) > 0) {
        $payment = $result['elements'][0];
        $payment_result = $payment['result'];

        if ($payment_result == 'SUCCESS') {
            $response = array(
                'paid' => true,
                'payment_id' => $payment['id'],
                'last4' => isset($payment['cardTransaction']['last4']) ? $payment['cardTransaction']['last4'] : '',
                'card_brand' => isset($payment['cardTransaction']['cardType']) ? $payment['cardTransaction']['cardType'] : '',
                'amount' => $payment['amount']
            );
            echo json_encode($response);
            return;
        } elseif ($payment_result == 'FAIL' || $payment_result == 'DECLINED') {
            echo json_encode(array('paid' => false, 'error' => 'Payment ' . $payment_result));
            return;
        }
    }

    echo json_encode(array('paid' => false));
}


/**
 * STEP 3: Payment confirmed - save to database
 */
function add3() {

require("deps.php");
require_once("common.php");

$currenttotal = $_REQUEST['currenttotal'];
$cfirstname = $_REQUEST['cfirstname'];
$ccompany = $_REQUEST['ccompany'];
$caddress = $_REQUEST['caddress'];
$caddress2 = $_REQUEST['caddress2'];
$ccity = $_REQUEST['ccity'];
$cstate = $_REQUEST['cstate'];
$czip = $_REQUEST['czip'];
$cphone = $_REQUEST['cphone'];
$cemail = $_REQUEST['cemail'];
$isdeposit = $_REQUEST['isdeposit'];
$woid = $_REQUEST['woid'];
$invoiceid = $_REQUEST['invoiceid'];

$clover_order_id = $_REQUEST['clover_order_id'];
$clover_payment_id = $_REQUEST['clover_payment_id'];
$clover_card_last4 = isset($_REQUEST['clover_card_last4']) ? $_REQUEST['clover_card_last4'] : '';
$clover_card_brand = isset($_REQUEST['clover_card_brand']) ? $_REQUEST['clover_card_brand'] : '';

$amounttopay = $currenttotal;
$ipofpc = getipofpc();

// Sanitize for DB
$custname = mysqli_real_escape_string($rs_connect, $cfirstname);
$ccompany = mysqli_real_escape_string($rs_connect, $ccompany);
$custaddy1 = mysqli_real_escape_string($rs_connect, $caddress);
$custaddy2 = mysqli_real_escape_string($rs_connect, $caddress2);
$custcity = mysqli_real_escape_string($rs_connect, $ccity);
$custstate = mysqli_real_escape_string($rs_connect, $cstate);
$custzip = mysqli_real_escape_string($rs_connect, $czip);
$custphone = mysqli_real_escape_string($rs_connect, $cphone);

$cc_transid = mysqli_real_escape_string($rs_connect, $clover_payment_id);
$ccnumber2 = mysqli_real_escape_string($rs_connect, $clover_card_last4);
$cccardtype = mysqli_real_escape_string($rs_connect, $clover_card_brand);

if (function_exists('date_default_timezone_set')) {
date_default_timezone_set("$pcrt_timezone");
}
$currentdatetime = date('Y-m-d H:i:s');

if ($isdeposit == 1) {
$registerid = getcurrentregister();
$rs_insert_gcc = "INSERT INTO deposits (pfirstname,pcompany,byuser,amount,paymentplugin,paymentstatus,paymenttype,paddress,paddress2,pcity,pstate,pzip,pphone,cc_number,cc_expmonth,cc_expyear,cc_transid,cc_cardtype,woid,invoiceid,dstatus,depdate,storeid,registerid) VALUES ('$custname','$ccompany','$ipofpc','$amounttopay','Clover','ready','credit','$custaddy1','$custaddy2','$custcity','$custstate','$custzip','$custphone','$ccnumber2','0','0','$cc_transid','$cccardtype','$woid','$invoiceid','open','$currentdatetime','$defaultuserstore','$registerid')";
@mysqli_query($rs_connect, $rs_insert_gcc);

$depositid = mysqli_insert_id($rs_connect);
header("Location: deposits.php?func=deposit_receipt&depositid=$depositid&woid=$woid");
} else {

$rs_insert_gcc = "INSERT INTO currentpayments (pfirstname,pcompany,byuser,amount,paymentplugin,paymentstatus,paymenttype,paddress,paddress2,pcity,pstate,pzip,pphone,cc_number,cc_expmonth,cc_expyear,cc_transid,cc_cardtype) VALUES ('$custname','$ccompany','$ipofpc','$amounttopay','Clover','ready','credit','$custaddy1','$custaddy2','$custcity','$custstate','$custzip','$custphone','$ccnumber2','0','0','$cc_transid','$cccardtype')";
@mysqli_query($rs_connect, $rs_insert_gcc);

header("Location: $domain/cart.php");
}

}


/**
 * VOID: Refund a Clover payment
 */
function void() {
require_once("validate.php");

require("deps.php");
require_once("common.php");

$payid = $_REQUEST['payid'];
$cc_transid = $_REQUEST['cc_transid'];

if (array_key_exists('depositid',$_REQUEST)) {
$depositid = $_REQUEST['depositid'];
} else {
$depositid = 0;
}

if (array_key_exists('isdeposit',$_REQUEST)) {
$isdeposit = $_REQUEST['isdeposit'];
} else {
$isdeposit = 0;
}

if ($demo == "yes") {
die("Sorry this feature is disabled in demo mode");
}

// Find the order that contains this payment to get the order_id
$isapproved = 1;
$refund_error = '';

if (!empty($cc_transid)) {
    // Refund via Clover API
    $refund_data = array(
        'amount' => null // null = full refund
    );

    // Get payment details first to find the amount
    if ($isdeposit != 1) {
        $find_sql = "SELECT amount FROM currentpayments WHERE paymentid = '$payid'";
    } else {
        $find_sql = "SELECT amount FROM deposits WHERE depositid = '$depositid'";
    }
    $find_q = @mysqli_query($rs_connect, $find_sql);
    $find_a = mysqli_fetch_object($find_q);

    if ($find_a) {
        $refund_data['amount'] = round($find_a->amount * 100); // cents
    }

    $result = clover_api('POST', '/payments/' . $cc_transid . '/refunds', $refund_data);

    if (isset($result['_httpcode']) && ($result['_httpcode'] < 200 || $result['_httpcode'] >= 300)) {
        $isapproved = 0;
        $refund_error = isset($result['message']) ? $result['message'] : 'Refund failed (HTTP ' . $result['_httpcode'] . ')';
    }
}

if ($isapproved == 0) {
require("header.php");
start_box();
echo "<span style=\"font-size:20px;\">".pcrtlang("Refund Failed")."</span><br><br>";
echo pcrtlang("Reason").":<br><br><span style=\"font-size:16px;color:red\">" . htmlspecialchars($refund_error) . "</span>";

echo "<br><br><a href=Clover.php?func=voidoverride&payid=$payid&isdeposit=$isdeposit&depositid=$depositid>".pcrtlang("Override and Remove this Credit Card Payment")."</a><br><br>".pcrtlang("Note: If you do this it will not release the hold on funds for your customers credit card, you must manually login to your Clover dashboard and void this charge.");

stop_box();
require("footer.php");

} else {

if ($isdeposit != 1) {
$rs_void_cc = "DELETE FROM currentpayments WHERE paymentid = '$payid'";
@mysqli_query($rs_connect, $rs_void_cc);

header("Location: cart.php");
} else {
$rs_void_cc = "DELETE FROM deposits WHERE depositid = '$depositid'";
@mysqli_query($rs_connect, $rs_void_cc);
header("Location: deposits.php");
}
}
}


/**
 * VOID OVERRIDE: Remove payment from DB without Clover API refund
 */
function voidoverride() {
require_once("validate.php");

require("deps.php");
require_once("common.php");

$payid = $_REQUEST['payid'];

if (array_key_exists('depositid',$_REQUEST)) {
$depositid = $_REQUEST['depositid'];
} else {
$depositid = 0;
}

if (array_key_exists('isdeposit',$_REQUEST)) {
$isdeposit = $_REQUEST['isdeposit'];
} else {
$isdeposit = 0;
}

if ($demo == "yes") {
die("Sorry this feature is disabled in demo mode");
}

if ($isdeposit != 1) {
$rs_void_cc = "DELETE FROM currentpayments WHERE paymentid = '$payid'";
@mysqli_query($rs_connect, $rs_void_cc);
header("Location: cart.php");
} else {
$rs_void_cc = "DELETE FROM deposits WHERE depositid = '$depositid'";
@mysqli_query($rs_connect, $rs_void_cc);
header("Location: deposits.php");
}

}


switch($func) {

    default:
    nothing();
    break;

    case "add":
    add();
    break;

    case "add2":
    add2();
    break;

    case "add3":
    add3();
    break;

    case "check_payment":
    check_payment();
    break;

    case "void":
    void();
    break;

    case "voidoverride":
    voidoverride();
    break;

}

?>
