<?php
/***************************************************************************
 *   Reports Viewer - Web page to browse and download daily/monthly reports
 *   URL: pos.pcpluscomputing.com/store/daily_reports_view.php
 ***************************************************************************/

// Handle file download before any HTML output
if (isset($_REQUEST['download'])) {
    require("deps.php");
    $report_folder = isset($DailyReportFolder) ? $DailyReportFolder : '/home/pos/daily_reports';
    $filename = basename($_REQUEST['download']); // prevent path traversal
    $filepath = $report_folder . '/' . $filename;

    if (file_exists($filepath) && pathinfo($filename, PATHINFO_EXTENSION) == 'csv') {
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . filesize($filepath));
        readfile($filepath);
        exit;
    }
}

require("header.php");

$report_folder = isset($DailyReportFolder) ? $DailyReportFolder : '/home/pos/daily_reports';

start_box();
echo "<h2>".pcrtlang("Daily & Monthly Reports")."</h2>";

// Get all CSV files from the reports folder
$files = array();
if (is_dir($report_folder)) {
    $dir = scandir($report_folder, SCANDIR_SORT_DESCENDING);
    foreach ($dir as $file) {
        if (pathinfo($file, PATHINFO_EXTENSION) == 'csv') {
            $files[] = $file;
        }
    }
}

if (empty($files)) {
    echo "<p>No reports generated yet. Reports are automatically created at 11:59 PM each night.</p>";
    echo "<p>You can also generate a report manually for any date by running:<br>";
    echo "<code>php daily_report.php 2026-04-15</code></p>";
} else {
    // Separate monthly and daily files
    $monthly = array();
    $daily = array();
    foreach ($files as $file) {
        if (strpos($file, 'MonthlyReport_') === 0) {
            $monthly[] = $file;
        } elseif (strpos($file, 'DailyReport_') === 0) {
            $daily[] = $file;
        }
    }

    // Monthly reports section
    if (!empty($monthly)) {
        echo "<h3 style='margin-top:20px; color:#4CAF50;'>Monthly Reports (Cumulative)</h3>";
        echo "<p style='color:#666; font-size:13px;'>All transactions for the month on one sheet - keeps growing as each day is added.</p>";
        echo "<table width='100%' cellpadding='8' cellspacing='0' border='1' style='border-collapse:collapse; font-size:14px;'>";
        echo "<tr style='background:#4CAF50; color:white;'>";
        echo "<th align='left'>Month</th><th align='left'>File</th><th align='right'>Size</th><th align='left'>Last Updated</th><th align='center'>Download</th>";
        echo "</tr>";

        $row_color = false;
        foreach ($monthly as $file) {
            $filepath = $report_folder . '/' . $file;
            $size = filesize($filepath);
            $modified = date('Y-m-d g:i A', filemtime($filepath));
            $month = str_replace(array('MonthlyReport_', '.csv'), '', $file);
            $bg = $row_color ? '#f9f9f9' : '#ffffff';
            $row_color = !$row_color;

            echo "<tr style='background:$bg;'>";
            echo "<td><strong>" . htmlspecialchars($month) . "</strong></td>";
            echo "<td>" . htmlspecialchars($file) . "</td>";
            echo "<td align='right'>" . round($size / 1024, 1) . " KB</td>";
            echo "<td>" . $modified . "</td>";
            echo "<td align='center'><a href='daily_reports_view.php?download=" . urlencode($file) . "' style='color:white; background:#4CAF50; padding:4px 12px; border-radius:4px; text-decoration:none;'>Download</a></td>";
            echo "</tr>";
        }
        echo "</table>";
    }

    // Daily reports section
    if (!empty($daily)) {
        echo "<h3 style='margin-top:30px; color:#2196F3;'>Daily Reports</h3>";
        echo "<p style='color:#666; font-size:13px;'>Individual daily breakdown - one file per day.</p>";
        echo "<table width='100%' cellpadding='8' cellspacing='0' border='1' style='border-collapse:collapse; font-size:14px;'>";
        echo "<tr style='background:#2196F3; color:white;'>";
        echo "<th align='left'>Date</th><th align='left'>Day</th><th align='right'>Size</th><th align='center'>Download</th>";
        echo "</tr>";

        $row_color = false;
        foreach ($daily as $file) {
            $filepath = $report_folder . '/' . $file;
            $size = filesize($filepath);
            $date = str_replace(array('DailyReport_', '.csv'), '', $file);
            $day_name = date('l', strtotime($date));
            $bg = $row_color ? '#f9f9f9' : '#ffffff';
            $row_color = !$row_color;

            echo "<tr style='background:$bg;'>";
            echo "<td><strong>" . htmlspecialchars($date) . "</strong></td>";
            echo "<td>" . $day_name . "</td>";
            echo "<td align='right'>" . round($size / 1024, 1) . " KB</td>";
            echo "<td align='center'><a href='daily_reports_view.php?download=" . urlencode($file) . "' style='color:white; background:#2196F3; padding:4px 12px; border-radius:4px; text-decoration:none;'>Download</a></td>";
            echo "</tr>";
        }
        echo "</table>";
    }
}

stop_box();
require("footer.php");
?>
