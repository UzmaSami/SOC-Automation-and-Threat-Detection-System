$logPath = "C:\UzmaSOC-Logs"
$outputFile = "$logPath\SOC-Dashboard.html"

# Import CSV
$brute = Import-Csv "$logPath\bruteforce_logs.csv" -ErrorAction SilentlyContinue
$priv  = Import-Csv "$logPath\privilege_logs.csv" -ErrorAction SilentlyContinue
$ps    = Import-Csv "$logPath\powershell_logs.csv" -ErrorAction SilentlyContinue
$admin = Import-Csv "$logPath\admin_logs.csv" -ErrorAction SilentlyContinue

# Counts (Fallback safely to 0 if CSV is missing or empty)
$bruteCount = if ($brute) { $brute.Count } else { 0 }
$privCount  = if ($priv)  { $priv.Count }  else { 0 }
$psCount    = if ($ps)    { $ps.Count }    else { 0 }
$adminCount = if ($admin) { $admin.Count } else { 0 }

# Convert to HTML fragments cleanly
$bruteTable = if ($brute) { $brute | ConvertTo-Html -Fragment } else { "<p style='color:#8b949e;'>No active Brute Force incidents recorded.</p>" }
$privTable  = if ($priv)  { $priv  | ConvertTo-Html -Fragment } else { "<p style='color:#3fb950;'>No unauthorized group changes detected.</p>" }
$psTable    = if ($ps)    { $ps    | ConvertTo-Html -Fragment } else { "<p style='color:#3fb950;'>No suspicious script patterns triggered alerts.</p>" }
$adminTable = if ($admin) { $admin | ConvertTo-Html -Fragment } else { "<p style='color:#8b949e;'>No administrative authentications found.</p>" }

# HTML Core Generation with MITRE Framework Mapping
$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Uzma Sami SOC Dashboard</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
    body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
    h1 { text-align: center; color: #58a6ff; margin-bottom: 5px; font-weight: 400; }
    .subtitle { text-align: center; color: #8b949e; font-size: 14px; margin-bottom: 30px; }
    
    .dashboard { display: flex; justify-content: space-between; gap: 15px; margin: 20px 0; }
    
    .card {
        background: #161b22;
        padding: 20px;
        border-radius: 8px;
        text-align: center;
        width: 23%;
        border: 1px solid #30363d;
        border-top: 4px solid #30363d;
        transition: transform 0.2s;
    }
    .card:hover { transform: translateY(-3px); }
    .card h3 { font-size: 14px; color: #8b949e; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
    .card .mitre-tag { display: inline-block; font-size: 11px; background: #21262d; color: #58a6ff; padding: 2px 8px; border-radius: 12px; margin-bottom: 12px; border: 1px solid #30363d; font-family: monospace; }
    .card p { font-size: 32px; font-weight: bold; color: #f0f6fc; margin: 0; }
    
    /* Dynamic status borders for matrix cards */
    .border-brute { border-top-color: #ff7b72; }
    .border-priv { border-top-color: #ff7b72; }
    .border-ps { border-top-color: #e3b341; }
    .border-admin { border-top-color: #3fb950; }

    .section { background: #161b22; margin: 25px 0; padding: 20px; border: 1px solid #30363d; border-radius: 8px; }
    .section h2 { color: #58a6ff; font-size: 18px; margin-top: 0; margin-bottom: 15px; padding-bottom: 8px; border-bottom: 1px solid #21262d; }
    .section h2 span.mitre-aside { float: right; font-size: 12px; color: #8b949e; font-family: monospace; font-weight: normal; margin-top: 4px; }
    
    /* Table Styling */
    table { border-collapse: collapse; width: 100%; font-size: 13px; margin-top: 10px; background: #0d1117; }
    th, td { border: 1px solid #30363d; padding: 10px 12px; text-align: left; }
    th { background-color: #1f242c; color: #c9d1d9; font-weight: 600; }
    tr:nth-child(even) { background-color: #161b22; }
    tr:hover { background-color: #21262d; }
    
    .chart-container { max-height: 280px; position: relative; width: 100%; }
</style>
</head>

<body>

<h1>Uzma Sami SOC Monitoring Dashboard</h1>
<div class="subtitle">Real-Time Threat Intelligence and MITRE ATT&CK Matrix Mapping Framework</div>

<div class="dashboard">
    <div class="card border-brute">
        <h3>Brute Force</h3>
        <div class="mitre-tag">Credential Access (T1110)</div>
        <p>$bruteCount</p>
    </div>
    <div class="card border-priv">
        <h3>Privilege Escalation</h3>
        <div class="mitre-tag">Persistence (T1098)</div>
        <p>$privCount</p>
    </div>
    <div class="card border-ps">
        <h3>PowerShell Alerts</h3>
        <div class="mitre-tag">Execution (T1059.001)</div>
        <p>$psCount</p>
    </div>
    <div class="card border-admin">
        <h3>Admin Logins</h3>
        <div class="mitre-tag">Valid Accounts (T1078)</div>
        <p>$adminCount</p>
    </div>
</div>

<div class="section">
    <h2>Security Event Overview Matrix</h2>
    <div class="chart-container">
        <canvas id="socChart"></canvas>
    </div>
</div>

<div class="section">
    <h2>Brute Force Logs <span class="mitre-aside">Tactics: Credential Access | Technique: T1110</span></h2>
    $bruteTable
</div>

<div class="section">
    <h2>Privilege Escalation Logs <span class="mitre-aside">Tactics: Persistence and PrivEsc | Technique: T1098</span></h2>
    $privTable
</div>

<div class="section">
    <h2>PowerShell High-Risk Activity <span class="mitre-aside">Tactics: Execution | Technique: T1059.001</span></h2>
    $psTable
</div>

<div class="section">
    <h2>Administrative Logins <span class="mitre-aside">Tactics: Defense Evasion | Technique: T1078</span></h2>
    $adminTable
</div>

<script>
var ctx = document.getElementById('socChart').getContext('2d');
var chart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: [
            'Brute Force (T1110)', 
            'Privilege Escalation (T1098)', 
            'PowerShell (T1059.001)', 
            'Admin Logins (T1078)'
        ],
        datasets: [{
            label: 'Active System Alarms',
            data: [$bruteCount, $privCount, $psCount, $adminCount],
            backgroundColor: [
                'rgba(255, 123, 114, 0.25)',  
                'rgba(255, 123, 114, 0.25)',  
                'rgba(227, 179, 65, 0.25)',   
                'rgba(63, 185, 80, 0.25)'     
            ],
            borderColor: [
                '#ff7b72', '#ff7b72', '#e3b341', '#3fb950'
            ],
            borderWidth: 1.5,
            borderRadius: 4
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { labels: { color: '#8b949e' } }
        },
        scales: {
            y: {
                beginAtZero: true,
                grid: { color: '#21262d' },
                ticks: { color: '#8b949e', stepSize: 1 }
            },
            x: {
                grid: { display: false },
                ticks: { color: '#8b949e' }
            }
        }
    }
});
</script>

</body>
</html>
"@

$html | Out-File $outputFile -Encoding UTF8
Write-Output "SOC Dashboard created: $outputFile"
