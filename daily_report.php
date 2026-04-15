<?php

/***************************************************************************
 *   Daily Auto-Close & Excel Report Generator
 *   Runs at 11:59 PM via cron to close the day and generate a daily
 *   Excel report with parts, labor, GST, and PST breakdown.
 *
 *   Cron: 59 23 * * * php /path/to/store/daily_report.php
 *   Can also be called manually: daily_report.php?func=generate&date=2026-04-12
 ***************************************************************************/

require_once("deps.php");

// Database connection (standalone - no session needed)
$rs_connect = mysqli_connect($dbhost, $dbuname, $dbpass, $dbname) or die("DB connection failed");
mysqli_query($rs_connect, "SET NAMES utf8");
mysqli_query($rs_connect, "SET SESSION sql_mode=''");

if (function_exists('date_default_timezone_set')) {
    date_default_timezone_set("$pcrt_timezone");
}

// Configuration
$report_folder = isset($daily_report_folder) ? $daily_report_folder : __DIR__ . '/daily_reports';

// Allow specifying date via URL param or CLI arg
if (php_sapi_name() == 'cli') {
    $report_date = isset($argv[1]) ? $argv[1] : date('Y-m-d');
} else {
    if (isset($_REQUEST['func']) && $_REQUEST['func'] == 'generate') {
        $report_date = isset($_REQUEST['date']) ? $_REQUEST['date'] : date('Y-m-d');
    } else {
        $report_date = date('Y-m-d');
    }
}

$date_start = $report_date . ' 00:00:00';
$date_end = $report_date . ' 23:59:59';

// Create report folder if it doesn't exist
if (!is_dir($report_folder)) {
    mkdir($report_folder, 0755, true);
}

/**
 * Get all tax definitions
 */
function get_tax_definitions($rs_connect) {
    $taxes = array();
    $q = mysqli_query($rs_connect, "SELECT * FROM taxes WHERE taxenabled = 1");
    while ($row = mysqli_fetch_object($q)) {
        $taxes[$row->taxid] = $row;
    }
    return $taxes;
}

/**
 * Fetch daily sales data with parts/labor/tax breakdown
 */
function get_daily_data($rs_connect, $date_start, $date_end) {
    $data = array(
        'receipts' => array(),
        'summary' => array(
            'total_parts' => 0,
            'total_labor' => 0,
            'total_parts_tax' => 0,
            'total_labor_tax' => 0,
            'total_refund_parts' => 0,
            'total_refund_labor' => 0,
            'total_refund_parts_tax' => 0,
            'total_refund_labor_tax' => 0,
            'grand_total' => 0,
            'grand_tax' => 0,
            'receipt_count' => 0,
            'payment_methods' => array()
        ),
        'tax_breakdown' => array() // Per tax name (GST, PST, etc.)
    );

    $taxes = get_tax_definitions($rs_connect);

    // Get all receipts for the day
    $sql = "SELECT r.*,
            GROUP_CONCAT(DISTINCT sp.paymentplugin) as payment_methods
            FROM receipts r
            LEFT JOIN savedpayments sp ON r.receipt_id = sp.receipt_id
            WHERE r.date_sold BETWEEN '$date_start' AND '$date_end'
            GROUP BY r.receipt_id
            ORDER BY r.date_sold ASC";
    $q = mysqli_query($rs_connect, $sql);

    while ($receipt = mysqli_fetch_object($q)) {
        $receipt_data = array(
            'receipt_id' => $receipt->receipt_id,
            'date' => $receipt->date_sold,
            'customer' => $receipt->person_name,
            'company' => $receipt->company,
            'grand_total' => $receipt->grandtotal,
            'grand_tax' => $receipt->grandtax,
            'payment_method' => $receipt->payment_methods,
            'woid' => $receipt->woid,
            'invoice_id' => $receipt->invoice_id,
            'parts' => 0,
            'labor' => 0,
            'parts_tax' => 0,
            'labor_tax' => 0,
            'refund_parts' => 0,
            'refund_labor' => 0,
            'items' => array()
        );

        // Get sold items for this receipt
        $items_sql = "SELECT si.*, s.itemname
                      FROM sold_items si
                      LEFT JOIN stock s ON si.stockid = s.stockid
                      WHERE si.receipt = '{$receipt->receipt_id}'";
        $items_q = mysqli_query($rs_connect, $items_sql);

        while ($item = mysqli_fetch_object($items_q)) {
            $item_data = array(
                'name' => ($item->sold_type == 'labor' || $item->sold_type == 'refundlabor')
                    ? $item->labor_desc : ($item->itemname ? $item->itemname : 'Item #' . $item->stockid),
                'type' => $item->sold_type,
                'price' => $item->sold_price,
                'tax' => $item->itemtax,
                'quantity' => $item->quantity,
                'unit_price' => $item->unit_price
            );

            $receipt_data['items'][] = $item_data;

            // Accumulate by type
            switch ($item->sold_type) {
                case 'purchase':
                    $receipt_data['parts'] += $item->sold_price;
                    $receipt_data['parts_tax'] += $item->itemtax;
                    $data['summary']['total_parts'] += $item->sold_price;
                    $data['summary']['total_parts_tax'] += $item->itemtax;
                    break;
                case 'labor':
                    $receipt_data['labor'] += $item->sold_price;
                    $receipt_data['labor_tax'] += $item->itemtax;
                    $data['summary']['total_labor'] += $item->sold_price;
                    $data['summary']['total_labor_tax'] += $item->itemtax;
                    break;
                case 'refund':
                    $receipt_data['refund_parts'] += abs($item->sold_price);
                    $data['summary']['total_refund_parts'] += abs($item->sold_price);
                    $data['summary']['total_refund_parts_tax'] += abs($item->itemtax);
                    break;
                case 'refundlabor':
                    $receipt_data['refund_labor'] += abs($item->sold_price);
                    $data['summary']['total_refund_labor'] += abs($item->sold_price);
                    $data['summary']['total_refund_labor_tax'] += abs($item->itemtax);
                    break;
            }

            // Tax breakdown by tax zone
            if ($item->taxex > 0 && isset($taxes[$item->taxex])) {
                $tax_name = $taxes[$item->taxex]->taxname;
                if (!isset($data['tax_breakdown'][$tax_name])) {
                    $data['tax_breakdown'][$tax_name] = 0;
                }
                $data['tax_breakdown'][$tax_name] += $item->itemtax;

                // Handle group/composite rates (GST + PST combined)
                if ($taxes[$item->taxex]->isgrouprate == 1 && !empty($taxes[$item->taxex]->compositerate)) {
                    $group_ids = @unserialize($taxes[$item->taxex]->compositerate);
                    if (is_array($group_ids)) {
                        // Remove parent group entry
                        unset($data['tax_breakdown'][$tax_name]);
                        // Add individual components
                        foreach ($group_ids as $sub_id) {
                            if (isset($taxes[$sub_id])) {
                                $sub_name = $taxes[$sub_id]->taxname;
                                $is_labor = ($item->sold_type == 'labor' || $item->sold_type == 'refundlabor');
                                $sub_rate = $is_labor ? $taxes[$sub_id]->taxrateservice : $taxes[$sub_id]->taxrategoods;
                                $sub_tax = $item->sold_price * $sub_rate;
                                if (!isset($data['tax_breakdown'][$sub_name])) {
                                    $data['tax_breakdown'][$sub_name] = 0;
                                }
                                $data['tax_breakdown'][$sub_name] += $sub_tax;
                            }
                        }
                    }
                }
            }
        }

        // Track payment methods
        if ($receipt->payment_methods) {
            $methods = explode(',', $receipt->payment_methods);
            foreach ($methods as $method) {
                $method = trim($method);
                if (!isset($data['summary']['payment_methods'][$method])) {
                    $data['summary']['payment_methods'][$method] = 0;
                }
                $data['summary']['payment_methods'][$method]++;
            }
        }

        $data['summary']['grand_total'] += $receipt->grandtotal;
        $data['summary']['grand_tax'] += $receipt->grandtax;
        $data['summary']['receipt_count']++;

        $data['receipts'][] = $receipt_data;
    }

    return $data;
}


/**
 * Generate Excel (CSV) report
 */
function generate_excel_report($data, $report_date, $report_folder) {
    $filename = 'DailyReport_' . $report_date . '.csv';
    $filepath = $report_folder . '/' . $filename;

    $fp = fopen($filepath, 'w');

    // Header
    fputcsv($fp, array('PC Plus Computing - Daily Sales Report'));
    fputcsv($fp, array('Date: ' . $report_date));
    fputcsv($fp, array('Generated: ' . date('Y-m-d H:i:s')));
    fputcsv($fp, array(''));

    // Summary section
    fputcsv($fp, array('=== DAILY SUMMARY ==='));
    fputcsv($fp, array(''));
    fputcsv($fp, array('Category', 'Amount'));

    $s = $data['summary'];
    $net_parts = $s['total_parts'] - $s['total_refund_parts'];
    $net_labor = $s['total_labor'] - $s['total_refund_labor'];
    $net_parts_tax = $s['total_parts_tax'] - $s['total_refund_parts_tax'];
    $net_labor_tax = $s['total_labor_tax'] - $s['total_refund_labor_tax'];

    fputcsv($fp, array('Parts/Products', number_format($net_parts, 2)));
    fputcsv($fp, array('Labor/Services', number_format($net_labor, 2)));
    fputcsv($fp, array('Subtotal', number_format($net_parts + $net_labor, 2)));
    fputcsv($fp, array(''));

    // Tax breakdown
    fputcsv($fp, array('=== TAX BREAKDOWN ==='));
    fputcsv($fp, array(''));
    fputcsv($fp, array('Tax Name', 'Amount'));

    foreach ($data['tax_breakdown'] as $tax_name => $tax_amount) {
        fputcsv($fp, array($tax_name, number_format($tax_amount, 2)));
    }

    fputcsv($fp, array('Total Tax', number_format($s['grand_tax'], 2)));
    fputcsv($fp, array(''));

    // Grand total
    fputcsv($fp, array('=== TOTALS ==='));
    fputcsv($fp, array(''));
    fputcsv($fp, array('Grand Total (incl. tax)', number_format($s['grand_total'], 2)));
    fputcsv($fp, array('Total Receipts', $s['receipt_count']));
    fputcsv($fp, array(''));

    // Refunds
    if ($s['total_refund_parts'] > 0 || $s['total_refund_labor'] > 0) {
        fputcsv($fp, array('=== REFUNDS ==='));
        fputcsv($fp, array('Parts Refunds', number_format($s['total_refund_parts'], 2)));
        fputcsv($fp, array('Labor Refunds', number_format($s['total_refund_labor'], 2)));
        fputcsv($fp, array(''));
    }

    // Payment methods
    fputcsv($fp, array('=== PAYMENT METHODS ==='));
    fputcsv($fp, array(''));
    fputcsv($fp, array('Method', 'Count'));
    foreach ($s['payment_methods'] as $method => $count) {
        fputcsv($fp, array($method, $count));
    }
    fputcsv($fp, array(''));

    // Individual receipts
    fputcsv($fp, array('=== RECEIPT DETAILS ==='));
    fputcsv($fp, array(''));
    fputcsv($fp, array('Receipt #', 'Time', 'Customer', 'Company', 'WO/Invoice', 'Parts', 'Labor', 'Tax', 'Total', 'Payment'));

    foreach ($data['receipts'] as $r) {
        fputcsv($fp, array(
            $r['receipt_id'],
            date('H:i:s', strtotime($r['date'])),
            $r['customer'],
            $r['company'],
            $r['woid'] . ($r['invoice_id'] ? '/' . $r['invoice_id'] : ''),
            number_format($r['parts'] - $r['refund_parts'], 2),
            number_format($r['labor'] - $r['refund_labor'], 2),
            number_format($r['parts_tax'] + $r['labor_tax'], 2),
            number_format($r['grand_total'], 2),
            $r['payment_method']
        ));
    }

    // Line item details
    fputcsv($fp, array(''));
    fputcsv($fp, array('=== LINE ITEM DETAILS ==='));
    fputcsv($fp, array(''));
    fputcsv($fp, array('Receipt #', 'Item', 'Type', 'Qty', 'Unit Price', 'Total', 'Tax'));

    foreach ($data['receipts'] as $r) {
        foreach ($r['items'] as $item) {
            fputcsv($fp, array(
                $r['receipt_id'],
                $item['name'],
                $item['type'],
                $item['quantity'],
                number_format($item['unit_price'], 2),
                number_format($item['price'], 2),
                number_format($item['tax'], 2)
            ));
        }
    }

    fclose($fp);

    return $filepath;
}


/**
 * Close register for the day (if not already closed)
 */
function auto_close_register($rs_connect, $report_date) {
    $date_start = $report_date . ' 00:00:00';
    $date_end = $report_date . ' 23:59:59';

    // Check if already closed today
    $check_sql = "SELECT * FROM regclose WHERE closeddate BETWEEN '$date_start' AND '$date_end' LIMIT 1";
    $check_q = mysqli_query($rs_connect, $check_sql);
    if (mysqli_num_rows($check_q) > 0) {
        return false; // Already closed
    }

    // Get register totals by payment plugin
    $sql = "SELECT sp.paymentplugin, SUM(sp.amount) as total, COUNT(*) as cnt
            FROM savedpayments sp
            INNER JOIN receipts r ON sp.receipt_id = r.receipt_id
            WHERE r.date_sold BETWEEN '$date_start' AND '$date_end'
            GROUP BY sp.paymentplugin";
    $q = mysqli_query($rs_connect, $sql);

    $closed_any = false;
    while ($row = mysqli_fetch_object($q)) {
        $plugin = mysqli_real_escape_string($rs_connect, $row->paymentplugin);
        $total = $row->total;
        $count = $row->cnt;

        $close_sql = "INSERT INTO regclose (registerid, storeid, paymentplugin, opendate, closeddate, closedby, counttotal, expectedtotal, variance, balanceforward, removedtotal, notes)
                      VALUES (0, 0, '$plugin', '$date_start', '$date_end', 'auto-close', '$count', '$total', '0', '0', '$total', 'Auto-closed by daily report')";
        mysqli_query($rs_connect, $close_sql);
        $closed_any = true;
    }

    return $closed_any;
}


/**
 * Append daily data to cumulative monthly CSV
 * One file per month that grows as each day is added
 */
function append_to_monthly_report($data, $report_date, $report_folder) {
    $month = date('Y-m', strtotime($report_date));
    $filename = 'MonthlyReport_' . $month . '.csv';
    $filepath = $report_folder . '/' . $filename;

    $is_new = !file_exists($filepath);
    $fp = fopen($filepath, 'a'); // append mode

    if ($is_new) {
        // Write header row only for new files
        fputcsv($fp, array('Date', 'Receipt #', 'Time', 'Customer', 'Company', 'WO/Invoice',
            'Item', 'Type', 'Qty', 'Unit Price', 'Item Total', 'Item Tax',
            'Receipt Parts', 'Receipt Labor', 'Receipt Tax', 'Receipt Total', 'Payment Method'));
    }

    // Write each receipt's line items as rows
    foreach ($data['receipts'] as $r) {
        $first_item = true;
        if (empty($r['items'])) {
            // Receipt with no line items
            fputcsv($fp, array(
                $report_date,
                $r['receipt_id'],
                date('H:i:s', strtotime($r['date'])),
                $r['customer'],
                $r['company'],
                $r['woid'] . ($r['invoice_id'] ? '/' . $r['invoice_id'] : ''),
                '', '', '', '', '', '',
                number_format($r['parts'] - $r['refund_parts'], 2),
                number_format($r['labor'] - $r['refund_labor'], 2),
                number_format($r['parts_tax'] + $r['labor_tax'], 2),
                number_format($r['grand_total'], 2),
                $r['payment_method']
            ));
        }
        foreach ($r['items'] as $item) {
            fputcsv($fp, array(
                $report_date,
                $r['receipt_id'],
                date('H:i:s', strtotime($r['date'])),
                $first_item ? $r['customer'] : '',
                $first_item ? $r['company'] : '',
                $first_item ? $r['woid'] . ($r['invoice_id'] ? '/' . $r['invoice_id'] : '') : '',
                $item['name'],
                $item['type'],
                $item['quantity'],
                number_format($item['unit_price'], 2),
                number_format($item['price'], 2),
                number_format($item['tax'], 2),
                $first_item ? number_format($r['parts'] - $r['refund_parts'], 2) : '',
                $first_item ? number_format($r['labor'] - $r['refund_labor'], 2) : '',
                $first_item ? number_format($r['parts_tax'] + $r['labor_tax'], 2) : '',
                $first_item ? number_format($r['grand_total'], 2) : '',
                $first_item ? $r['payment_method'] : ''
            ));
            $first_item = false;
        }
    }

    // Add daily summary row
    $s = $data['summary'];
    fputcsv($fp, array(
        $report_date, '', '', '', '', '',
        '--- DAY TOTAL ---', '', '', '',
        '', '',
        number_format($s['total_parts'] - $s['total_refund_parts'], 2),
        number_format($s['total_labor'] - $s['total_refund_labor'], 2),
        number_format($s['grand_tax'], 2),
        number_format($s['grand_total'], 2),
        $s['receipt_count'] . ' receipts'
    ));

    fclose($fp);
    return $filepath;
}


// Main execution
$data = get_daily_data($rs_connect, $date_start, $date_end);

if ($data['summary']['receipt_count'] > 0) {
    // Generate daily report
    $report_path = generate_excel_report($data, $report_date, $report_folder);

    // Append to monthly cumulative report
    $monthly_path = append_to_monthly_report($data, $report_date, $report_folder);

    // Auto-close register
    $closed = auto_close_register($rs_connect, $report_date);

    if (php_sapi_name() == 'cli') {
        echo "Daily Report for $report_date\n";
        echo "Receipts: {$data['summary']['receipt_count']}\n";
        echo "Parts: $" . number_format($data['summary']['total_parts'], 2) . "\n";
        echo "Labor: $" . number_format($data['summary']['total_labor'], 2) . "\n";
        echo "Tax: $" . number_format($data['summary']['grand_tax'], 2) . "\n";
        foreach ($data['tax_breakdown'] as $name => $amt) {
            echo "  $name: $" . number_format($amt, 2) . "\n";
        }
        echo "Total: $" . number_format($data['summary']['grand_total'], 2) . "\n";
        echo "Report saved: $report_path\n";
        echo "Register closed: " . ($closed ? "Yes" : "Already closed") . "\n";
    } else {
        header('Content-Type: application/json');
        echo json_encode(array(
            'success' => true,
            'date' => $report_date,
            'receipts' => $data['summary']['receipt_count'],
            'parts' => $data['summary']['total_parts'],
            'labor' => $data['summary']['total_labor'],
            'tax' => $data['summary']['grand_tax'],
            'tax_breakdown' => $data['tax_breakdown'],
            'total' => $data['summary']['grand_total'],
            'report_path' => $report_path,
            'register_closed' => $closed
        ));
    }
} else {
    if (php_sapi_name() == 'cli') {
        echo "No sales for $report_date - no report generated.\n";
    } else {
        header('Content-Type: application/json');
        echo json_encode(array(
            'success' => true,
            'date' => $report_date,
            'receipts' => 0,
            'message' => 'No sales for this date'
        ));
    }
}

mysqli_close($rs_connect);

?>
