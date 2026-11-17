# dsh-privacy-guard — 原生认证对话框（Windows PowerShell 5.1 / WinForms）
#
# 用法（由主机端 src/dialog.mjs 调用）：
#   powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File dialog.ps1 `
#       -RequestPath <req.json> -ResponsePath <res.json>
#
# 请求 JSON 字段：
#   mode            'auth' | 'setup' | 'message'
#   title           窗口标题
#   heading         主标题（粗体大字）
#   details         详细说明（只读多行框；auth 模式）
#   intro           说明文字（setup/message 模式）
#   error           错误提示（红字，可选）
#   allowRemember   是否显示「记住本次授权」复选框
#   rememberText    复选框文案
#   timeoutSec      自动关闭秒数（<=0 表示不超时）
#   minLength       setup 模式最小密码长度
#   okText / cancelText  按钮文案
#
# 响应 JSON：{ decision: 'allow'|'deny'|'timeout'|'ok'|'cancel', password?: string, remember?: bool }

param(
  [Parameter(Mandatory = $true)][string]$RequestPath,
  [Parameter(Mandatory = $true)][string]$ResponsePath
)

$ErrorActionPreference = 'Stop'
$script:result = @{ decision = 'deny' }

function Write-Response {
  param([hashtable]$Payload)
  try {
    $json = $Payload | ConvertTo-Json -Compress -Depth 8
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ResponsePath, $json, $encoding)
  } catch {
    # 写不出去时至少留下空响应，主机端会按 deny 处理
  }
}

try {
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing

  $req = Get-Content -LiteralPath $RequestPath -Raw -Encoding UTF8 | ConvertFrom-Json
  $mode = [string]$req.mode
  if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'auth' }

  $title = if ($req.title) { [string]$req.title } else { '隐私守卫 — 身份认证' }
  $okText = if ($req.okText) { [string]$req.okText } else { '允许' }
  $cancelText = if ($req.cancelText) { [string]$req.cancelText } else { '拒绝' }
  $timeoutSec = 0
  if ($null -ne $req.timeoutSec) { $timeoutSec = [int]$req.timeoutSec }

  $fontName = 'Microsoft YaHei UI'
  $form = New-Object System.Windows.Forms.Form
  $form.Text = $title
  $form.Font = New-Object System.Drawing.Font($fontName, 9.75)
  $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
  $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
  $form.MaximizeBox = $false
  $form.MinimizeBox = $false
  $form.ShowIcon = $false
  $form.TopMost = $true
  $form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
  $form.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)
  $form.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)

  $heading = New-Object System.Windows.Forms.Label
  $heading.Font = New-Object System.Drawing.Font($fontName, 13, [System.Drawing.FontStyle]::Bold)
  $heading.ForeColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
  $heading.AutoSize = $false
  $heading.Text = if ($req.heading) { [string]$req.heading } else { 'AI 请求访问您的隐私数据' }
  $form.Controls.Add($heading)

  $sub = New-Object System.Windows.Forms.Label
  $sub.Font = New-Object System.Drawing.Font($fontName, 9.75)
  $sub.ForeColor = [System.Drawing.Color]::FromArgb(96, 96, 96)
  $sub.AutoSize = $false
  $form.Controls.Add($sub)

  $details = New-Object System.Windows.Forms.TextBox
  $details.Multiline = $true
  $details.ReadOnly = $true
  $details.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
  $details.BackColor = [System.Drawing.Color]::White
  $details.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
  $details.Font = New-Object System.Drawing.Font($fontName, 9.75)
  $details.Text = if ($req.details) { [string]$req.details } else { '' }
  $form.Controls.Add($details)

  $errorLabel = New-Object System.Windows.Forms.Label
  $errorLabel.AutoSize = $false
  $errorLabel.ForeColor = [System.Drawing.Color]::FromArgb(200, 40, 40)
  $errorLabel.Font = New-Object System.Drawing.Font($fontName, 9.75)
  $errorLabel.Text = if ($req.error) { [string]$req.error } else { '' }
  $form.Controls.Add($errorLabel)

  $pwdLabel = New-Object System.Windows.Forms.Label
  $pwdLabel.AutoSize = $false
  $pwdLabel.Text = if ($mode -eq 'setup') { '设置隐私密码' } else { '隐私密码' }
  $form.Controls.Add($pwdLabel)

  $pwd = New-Object System.Windows.Forms.TextBox
  $pwd.UseSystemPasswordChar = $true
  $pwd.Font = New-Object System.Drawing.Font($fontName, 11)
  $pwd.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
  $form.Controls.Add($pwd)

  $pwd2Label = New-Object System.Windows.Forms.Label
  $pwd2Label.AutoSize = $false
  $pwd2Label.Text = '再次输入'
  $form.Controls.Add($pwd2Label)

  $pwd2 = New-Object System.Windows.Forms.TextBox
  $pwd2.UseSystemPasswordChar = $true
  $pwd2.Font = New-Object System.Drawing.Font($fontName, 11)
  $pwd2.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
  $form.Controls.Add($pwd2)

  $strength = New-Object System.Windows.Forms.Label
  $strength.AutoSize = $false
  $strength.ForeColor = [System.Drawing.Color]::FromArgb(96, 96, 96)
  $strength.Font = New-Object System.Drawing.Font($fontName, 9)
  $form.Controls.Add($strength)

  $remember = New-Object System.Windows.Forms.CheckBox
  $remember.AutoSize = $false
  $remember.Text = if ($req.rememberText) { [string]$req.rememberText } else { '记住本次授权（有效期内同一位置不再询问）' }
  $remember.Checked = $true
  $form.Controls.Add($remember)

  $countdown = New-Object System.Windows.Forms.Label
  $countdown.AutoSize = $false
  $countdown.ForeColor = [System.Drawing.Color]::FromArgb(130, 130, 130)
  $form.Controls.Add($countdown)

  $btnOk = New-Object System.Windows.Forms.Button
  $btnOk.Text = $okText
  $btnOk.FlatStyle = [System.Windows.Forms.FlatStyle]::System
  $btnOk.Font = New-Object System.Drawing.Font($fontName, 10)
  $form.Controls.Add($btnOk)

  $btnCancel = New-Object System.Windows.Forms.Button
  $btnCancel.Text = $cancelText
  $btnCancel.FlatStyle = [System.Windows.Forms.FlatStyle]::System
  $btnCancel.Font = New-Object System.Drawing.Font($fontName, 10)
  $form.Controls.Add($btnCancel)

  # ---- 布局（96 DPI 基准，AutoScaleMode=Dpi 负责缩放） ----
  if ($mode -eq 'auth') {
    $form.ClientSize = New-Object System.Drawing.Size(640, 520)
    $heading.SetBounds(20, 18, 600, 30)
    $sub.SetBounds(20, 50, 600, 22)
    $details.SetBounds(20, 78, 600, 250)
    $errorLabel.SetBounds(20, 334, 600, 22)
    $pwdLabel.SetBounds(20, 362, 100, 24)
    $pwd.SetBounds(120, 358, 500, 30)
    $remember.SetBounds(120, 398, 500, 26)
    $countdown.SetBounds(20, 470, 360, 22)
    $btnCancel.SetBounds(430, 462, 90, 34)
    $btnOk.SetBounds(530, 462, 90, 34)
    $pwd2Label.Visible = $false
    $pwd2.Visible = $false
    $strength.Visible = $false
    if ($req.allowRemember -eq $false) { $remember.Visible = $false }
    $sub.Text = if ($req.sub) { [string]$req.sub } else { '请确认下方内容，输入隐私密码后才允许访问。' }
    $form.AcceptButton = $btnOk
    $form.CancelButton = $btnCancel
  } elseif ($mode -eq 'setup') {
    $form.ClientSize = New-Object System.Drawing.Size(640, 460)
    $heading.SetBounds(20, 18, 600, 30)
    $sub.SetBounds(20, 50, 600, 48)
    $sub.Text = if ($req.intro) { [string]$req.intro } else { '请设置一个只属于你的隐私密码。它用于加密本机隐私库，DSH 与 AI 都无法读取。' }
    $details.Visible = $false
    $errorLabel.SetBounds(20, 104, 600, 22)
    $pwdLabel.SetBounds(20, 136, 120, 24)
    $pwd.SetBounds(140, 132, 480, 30)
    $pwd2Label.SetBounds(20, 176, 120, 24)
    $pwd2.SetBounds(140, 172, 480, 30)
    $strength.SetBounds(140, 208, 480, 22)
    $remember.Visible = $false
    $countdown.SetBounds(20, 410, 360, 22)
    $btnCancel.SetBounds(430, 402, 90, 34)
    $btnOk.SetBounds(530, 402, 90, 34)
    $btnOk.Text = if ($req.okText) { [string]$req.okText } else { '保存密码' }
    $form.AcceptButton = $btnOk
    $form.CancelButton = $btnCancel
  } else {
    $form.ClientSize = New-Object System.Drawing.Size(640, 340)
    $heading.SetBounds(20, 18, 600, 30)
    $sub.SetBounds(20, 50, 600, 24)
    $sub.Text = ''
    $details.Visible = $false
    $errorLabel.Visible = $false
    $pwdLabel.Visible = $false
    $pwd.Visible = $false
    $pwd2Label.Visible = $false
    $pwd2.Visible = $false
    $strength.Visible = $false
    $remember.Visible = $false
    $countdown.Visible = $false
    $btnCancel.Visible = $false
    $btnOk.SetBounds(530, 280, 90, 34)
    $btnOk.Text = '知道了'
    $form.AcceptButton = $btnOk
    $bodyLabel = New-Object System.Windows.Forms.Label
    $bodyLabel.AutoSize = $false
    $bodyLabel.SetBounds(20, 80, 600, 180)
    $bodyLabel.Font = New-Object System.Drawing.Font($fontName, 10)
    $bodyLabel.Text = if ($req.details) { [string]$req.details } else { '' }
    $form.Controls.Add($bodyLabel)
  }

  # ---- 密码强度提示 ----
  $updateStrength = {
    if ($mode -ne 'setup') { return }
    $value = [string]$pwd.Text
    $score = 0
    if ($value.Length -ge 8) { $score++ }
    if ($value.Length -ge 12) { $score++ }
    if ($value -match '[a-z]' -and $value -match '[A-Z]') { $score++ }
    if ($value -match '\d') { $score++ }
    if ($value -match '[^A-Za-z0-9]') { $score++ }
    $labels = @('太短', '较弱', '一般', '良好', '很强', '非常强')
    $idx = [Math]::Min($score, 5)
    $strength.Text = '强度：' + $labels[$idx]
    if ($idx -le 1) { $strength.ForeColor = [System.Drawing.Color]::FromArgb(200, 40, 40) }
    elseif ($idx -le 3) { $strength.ForeColor = [System.Drawing.Color]::FromArgb(190, 120, 0) }
    else { $strength.ForeColor = [System.Drawing.Color]::FromArgb(20, 130, 60) }
  }
  $pwd.Add_TextChanged($updateStrength)
  & $updateStrength

  # ---- 超时倒计时 ----
  $script:remaining = $timeoutSec
  $timer = New-Object System.Windows.Forms.Timer
  $timer.Interval = 1000
  if ($timeoutSec -gt 0 -and $mode -ne 'message') {
    $countdown.Text = "剩余 $timeoutSec 秒后自动拒绝"
    $timer.Add_Tick({
      $script:remaining = $script:remaining - 1
      if ($script:remaining -le 0) {
        $timer.Stop()
        $script:result = @{ decision = 'timeout' }
        $form.Close()
      } else {
        $countdown.Text = "剩余 $script:remaining 秒后自动拒绝"
      }
    })
    $timer.Start()
  }

  # ---- 按钮逻辑 ----
  $btnCancel.Add_Click({
    $script:result = @{ decision = 'cancel' }
    $form.Close()
  })

  $btnOk.Add_Click({
    if ($mode -eq 'setup') {
      $value = [string]$pwd.Text
      $confirm = [string]$pwd2.Text
      $minLength = 8
      if ($null -ne $req.minLength) { $minLength = [int]$req.minLength }
      if ($value.Length -lt $minLength) {
        $errorLabel.Text = "密码至少 $minLength 位"
        return
      }
      if ($value -ne $confirm) {
        $errorLabel.Text = '两次输入的密码不一致'
        return
      }
      $script:result = @{ decision = 'ok'; password = $value }
      $form.Close()
      return
    }
    if ($mode -eq 'message') {
      $script:result = @{ decision = 'ok' }
      $form.Close()
      return
    }
    $value = [string]$pwd.Text
    if ([string]::IsNullOrEmpty($value)) {
      $errorLabel.Text = '请输入隐私密码'
      return
    }
    $script:result = @{ decision = 'allow'; password = $value; remember = [bool]$remember.Checked }
    $form.Close()
  })

  $form.Add_FormClosing({
    param($sender, $eventArgs)
    if ($script:result.decision -eq 'allow' -or $script:result.decision -eq 'ok' -or $script:result.decision -eq 'deny' -or $script:result.decision -eq 'timeout') {
      return
    }
    $script:result = @{ decision = 'cancel' }
  })

  $form.Add_Shown({
    $form.Activate()
    $form.BringToFront()
    if ($mode -ne 'message') { $pwd.Focus() } else { $btnOk.Focus() }
    try { [System.Media.SystemSounds]::Exclamation.Play() } catch { }
  })

  try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch { }

  [void]$form.ShowDialog()
  $timer.Stop()
  Write-Response $script:result
} catch {
  Write-Response @{ decision = 'deny'; error = ($_.Exception.Message) }
}
