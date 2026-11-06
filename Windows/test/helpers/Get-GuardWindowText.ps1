Add-Type -AssemblyName UIAutomationClient
$root = [System.Windows.Automation.AutomationElement]::RootElement
$windows = $root.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
foreach ($window in $windows) {
  $name = $window.Current.Name
  if ($name -notmatch 'Claude|Guard|Setup|Uninstall|Error') { continue }
  $result = [ordered]@{ name = $name; className = $window.Current.ClassName; controlType = $window.Current.ControlType.ProgrammaticName; children = @() }
  $children = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
  foreach ($child in $children) {
    if ($child.Current.Name) { $result.children += $child.Current.Name }
  }
  $result | ConvertTo-Json -Depth 4 -Compress
}
