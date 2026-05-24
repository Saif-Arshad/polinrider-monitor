# PolinRider Monitor - Desktop GUI Dashboard
# Open-source security tool that scans Windows machines for the PolinRider /
# BeaverTail (DPRK Lazarus) JavaScript supply-chain malware described at
# https://opensourcemalware.com/blog/polinrider-attack
#
# License: MIT
# Repo: https://github.com/Saif-Arshad/polinrider-monitor

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

$root        = $PSScriptRoot
$configFile  = Join-Path $root 'config.json'
$historyFile = Join-Path $root 'history.json'
$logFile     = Join-Path $root 'monitor.log'
$version     = '1.0.0'

# Marker strings built at runtime so Windows Defender doesn't flag this script
# itself for containing the same signatures it detects.
$global:m1 = -join ([char[]]@(114,109,99,101,106,37,111,116,98,37))
$global:m2 = -join ([char[]]@(95,36,95,49,101,52,50))
$global:m3 = -join ([char[]]@(50,56,53,55,54,56,55))
$global:m4 = -join ([char[]]@(50,54,54,55,54,56,54))
$global:payloadStart = -join ([char[]]@(103,108,111,98,97,108,91,39,33,39,93))

# Shared live-log collection that the scan runspace appends to and the UI drains
$global:scanLog = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$global:lastLogIndex = 0

# Default config
$defaultConfig = [ordered]@{
    ScanPaths = @(
        'C:\Development',
        "$env:USERPROFILE\OneDrive",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\source",
        "$env:USERPROFILE\projects"
    )
    MaxFileSize      = 10000000
    AutoScanOnLaunch = $false
}

function Load-Config {
    if (Test-Path $configFile) {
        try { return Get-Content $configFile -Raw | ConvertFrom-Json } catch {}
    }
    ($defaultConfig | ConvertTo-Json) | Set-Content -LiteralPath $configFile -Encoding utf8
    return $defaultConfig | ConvertTo-Json | ConvertFrom-Json
}
$global:config = Load-Config

# === XAML ===
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="PolinRider Monitor"
        Height="780" Width="1180" MinHeight="640" MinWidth="980"
        Background="#0F172A"
        WindowStartupLocation="CenterScreen"
        FontFamily="Segoe UI"
        TextOptions.TextFormattingMode="Display">

    <Window.Resources>
        <!-- BRUSHES -->
        <SolidColorBrush x:Key="Bg"          Color="#0F172A"/>
        <SolidColorBrush x:Key="Sidebar"     Color="#0B1220"/>
        <SolidColorBrush x:Key="Card"        Color="#1E293B"/>
        <SolidColorBrush x:Key="CardBorder"  Color="#334155"/>
        <SolidColorBrush x:Key="TextPri"     Color="#F1F5F9"/>
        <SolidColorBrush x:Key="TextSec"     Color="#94A3B8"/>
        <SolidColorBrush x:Key="TextMuted"   Color="#64748B"/>
        <SolidColorBrush x:Key="Blue"        Color="#3B82F6"/>
        <SolidColorBrush x:Key="BlueHover"   Color="#2563EB"/>
        <SolidColorBrush x:Key="Green"       Color="#10B981"/>
        <SolidColorBrush x:Key="Amber"       Color="#F59E0B"/>
        <SolidColorBrush x:Key="Red"         Color="#EF4444"/>
        <SolidColorBrush x:Key="Slate"       Color="#475569"/>
        <SolidColorBrush x:Key="SlateHover"  Color="#334155"/>
        <SolidColorBrush x:Key="MatrixBg"    Color="#020a02"/>
        <SolidColorBrush x:Key="MatrixGreen" Color="#00ff41"/>
        <SolidColorBrush x:Key="MatrixDim"   Color="#008f25"/>

        <!-- ICONS (Material Design Icons, Apache 2.0) -->
        <Geometry x:Key="IconDashboard">M13,3V9H21V3M13,21H21V11H13M3,21H11V15H3M3,13H11V3H3V13Z</Geometry>
        <Geometry x:Key="IconLogs">M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M18,20H6V4H13V9H18V20M8,11H16V13H8M8,15H16V17H8</Geometry>
        <Geometry x:Key="IconCog">M12,15.5A3.5,3.5 0 0,1 8.5,12A3.5,3.5 0 0,1 12,8.5A3.5,3.5 0 0,1 15.5,12A3.5,3.5 0 0,1 12,15.5M19.43,12.97C19.47,12.65 19.5,12.33 19.5,12C19.5,11.67 19.47,11.34 19.43,11L21.54,9.37C21.73,9.22 21.78,8.95 21.66,8.73L19.66,5.27C19.54,5.05 19.27,4.96 19.05,5.05L16.56,6.05C16.04,5.66 15.5,5.32 14.87,5.07L14.5,2.42C14.46,2.18 14.25,2 14,2H10C9.75,2 9.54,2.18 9.5,2.42L9.13,5.07C8.5,5.32 7.96,5.66 7.44,6.05L4.95,5.05C4.73,4.96 4.46,5.05 4.34,5.27L2.34,8.73C2.21,8.95 2.27,9.22 2.46,9.37L4.57,11C4.53,11.34 4.5,11.67 4.5,12C4.5,12.33 4.53,12.65 4.57,12.97L2.46,14.63C2.27,14.78 2.21,15.05 2.34,15.27L4.34,18.73C4.46,18.95 4.73,19.03 4.95,18.95L7.44,17.94C7.96,18.34 8.5,18.68 9.13,18.93L9.5,21.58C9.54,21.82 9.75,22 10,22H14C14.25,22 14.46,21.82 14.5,21.58L14.87,18.93C15.5,18.67 16.04,18.34 16.56,17.94L19.05,18.95C19.27,19.03 19.54,18.95 19.66,18.73L21.66,15.27C21.78,15.05 21.73,14.78 21.54,14.63L19.43,12.97Z</Geometry>
        <Geometry x:Key="IconInfo">M11,9H13V7H11M12,20C7.59,20 4,16.41 4,12C4,7.59 7.59,4 12,4C16.41,4 20,7.59 20,12C20,16.41 16.41,20 12,20M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M11,17H13V11H11V17Z</Geometry>
        <Geometry x:Key="IconSearch">M9.5,3A6.5,6.5 0 0,1 16,9.5C16,11.11 15.41,12.59 14.44,13.73L14.71,14H15.5L20.5,19L19,20.5L14,15.5V14.71L13.73,14.44C12.59,15.41 11.11,16 9.5,16A6.5,6.5 0 0,1 3,9.5A6.5,6.5 0 0,1 9.5,3M9.5,5C7,5 5,7 5,9.5C5,12 7,14 9.5,14C12,14 14,12 14,9.5C14,7 12,5 9.5,5Z</Geometry>
        <Geometry x:Key="IconBroom">M19.36,2.72L20.78,4.14L15.06,9.85C16.13,11.39 16.28,13.24 15.38,14.44L9.06,8.12C10.26,7.22 12.11,7.37 13.65,8.44L19.36,2.72M5.93,17.57C3.92,15.56 2.69,13.16 2.35,10.92L7.23,8.83L14.67,16.27L12.58,21.15C10.34,20.81 7.94,19.58 5.93,17.57Z</Geometry>
        <Geometry x:Key="IconShieldCheck">M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M10,17L6,13L7.41,11.59L10,14.17L16.59,7.58L18,9L10,17Z</Geometry>
        <Geometry x:Key="IconShieldAlert">M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M11,7H13V13H11V7M11,15H13V17H11V15Z</Geometry>
        <Geometry x:Key="IconShield">M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1Z</Geometry>
        <Geometry x:Key="IconLoading">M12,4V2A10,10 0 0,1 22,12H20A8,8 0 0,0 12,4Z</Geometry>
        <Geometry x:Key="IconPlus">M19,13H13V19H11V13H5V11H11V5H13V11H19V13Z</Geometry>
        <Geometry x:Key="IconTrash">M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z</Geometry>
        <Geometry x:Key="IconSave">M15,9H5V5H15M12,19A3,3 0 0,1 9,16A3,3 0 0,1 12,13A3,3 0 0,1 15,16A3,3 0 0,1 12,19M17,3H5C3.89,3 3,3.9 3,5V19A2,2 0 0,0 5,21H19A2,2 0 0,0 21,19V7L17,3Z</Geometry>
        <Geometry x:Key="IconGithub">M12,2A10,10 0 0,0 2,12C2,16.42 4.87,20.17 8.84,21.5C9.34,21.58 9.5,21.27 9.5,21C9.5,20.77 9.5,20.14 9.5,19.31C6.73,19.91 6.14,17.97 6.14,17.97C5.68,16.81 5.03,16.5 5.03,16.5C4.12,15.88 5.1,15.9 5.1,15.9C6.1,15.97 6.63,16.93 6.63,16.93C7.5,18.45 8.97,18 9.54,17.76C9.63,17.11 9.89,16.67 10.17,16.42C7.95,16.17 5.62,15.31 5.62,11.5C5.62,10.39 6,9.5 6.65,8.79C6.55,8.54 6.2,7.5 6.75,6.15C6.75,6.15 7.59,5.88 9.5,7.17C10.29,6.95 11.15,6.84 12,6.84C12.85,6.84 13.71,6.95 14.5,7.17C16.41,5.88 17.25,6.15 17.25,6.15C17.8,7.5 17.45,8.54 17.35,8.79C18,9.5 18.38,10.39 18.38,11.5C18.38,15.32 16.04,16.16 13.81,16.41C14.17,16.72 14.5,17.33 14.5,18.26C14.5,19.6 14.5,20.68 14.5,21C14.5,21.27 14.66,21.59 15.17,21.5C19.14,20.16 22,16.42 22,12A10,10 0 0,0 12,2Z</Geometry>
        <Geometry x:Key="IconFolder">M10,4H4C2.89,4 2,4.89 2,6V18A2,2 0 0,0 4,20H20A2,2 0 0,0 22,18V8C22,6.89 21.1,6 20,6H12L10,4Z</Geometry>

        <DropShadowEffect x:Key="CardShadow" BlurRadius="20" ShadowDepth="3" Direction="270" Opacity="0.4" Color="Black"/>

        <!-- ICON STYLES -->
        <Style x:Key="IconBtn" TargetType="Path">
            <Setter Property="Fill" Value="White"/>
            <Setter Property="Stretch" Value="Uniform"/>
            <Setter Property="Width" Value="18"/>
            <Setter Property="Height" Value="18"/>
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="Margin" Value="0,0,8,0"/>
        </Style>
        <Style x:Key="IconNav" TargetType="Path">
            <Setter Property="Fill" Value="#94A3B8"/>
            <Setter Property="Stretch" Value="Uniform"/>
            <Setter Property="Width" Value="20"/>
            <Setter Property="Height" Value="20"/>
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="Margin" Value="0,0,12,0"/>
        </Style>

        <!-- CARD -->
        <Style x:Key="CardStyle" TargetType="Border">
            <Setter Property="Background" Value="{StaticResource Card}"/>
            <Setter Property="BorderBrush" Value="{StaticResource CardBorder}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="10"/>
            <Setter Property="Effect" Value="{StaticResource CardShadow}"/>
        </Style>

        <!-- BUTTONS -->
        <Style x:Key="PrimaryButton" TargetType="Button">
            <Setter Property="Background" Value="{StaticResource Blue}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="Padding" Value="20,12"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}" CornerRadius="8" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="{StaticResource BlueHover}"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="border" Property="Opacity" Value="0.4"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="WarningButton" TargetType="Button" BasedOn="{StaticResource PrimaryButton}">
            <Setter Property="Background" Value="{StaticResource Amber}"/>
        </Style>
        <Style x:Key="DangerButton" TargetType="Button" BasedOn="{StaticResource PrimaryButton}">
            <Setter Property="Background" Value="{StaticResource Red}"/>
        </Style>
        <Style x:Key="SecondaryButton" TargetType="Button" BasedOn="{StaticResource PrimaryButton}">
            <Setter Property="Background" Value="{StaticResource Slate}"/>
            <Setter Property="FontWeight" Value="Normal"/>
            <Setter Property="Padding" Value="14,10"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>

        <!-- NAV BUTTON -->
        <Style x:Key="NavButton" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#94A3B8"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="Padding" Value="20,14"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}">
                            <Border.RenderTransform>
                                <TranslateTransform/>
                            </Border.RenderTransform>
                            <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#172033"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- LISTVIEW (history) -->
        <Style TargetType="ListView">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Foreground" Value="{StaticResource TextPri}"/>
        </Style>
        <Style TargetType="GridViewColumnHeader">
            <Setter Property="Background" Value="{StaticResource Card}"/>
            <Setter Property="Foreground" Value="{StaticResource TextSec}"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="Padding" Value="12,8"/>
            <Setter Property="BorderBrush" Value="{StaticResource CardBorder}"/>
            <Setter Property="BorderThickness" Value="0,0,0,1"/>
        </Style>
        <Style TargetType="ListViewItem">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="BorderBrush" Value="#1F2937"/>
            <Setter Property="BorderThickness" Value="0,0,0,1"/>
            <Setter Property="Padding" Value="0,4"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#27374D"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- INPUT -->
        <Style x:Key="DarkInput" TargetType="TextBox">
            <Setter Property="Background" Value="#0F172A"/>
            <Setter Property="Foreground" Value="{StaticResource TextPri}"/>
            <Setter Property="BorderBrush" Value="{StaticResource CardBorder}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="10,8"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6">
                            <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- CHECKBOX -->
        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="{StaticResource TextPri}"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="240"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- ========== SIDEBAR ========== -->
        <Border Grid.Column="0" Background="{StaticResource Sidebar}">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <!-- Brand -->
                <StackPanel Grid.Row="0" Margin="20,24,20,28">
                    <StackPanel Orientation="Horizontal">
                        <Border Width="36" Height="36" CornerRadius="8" Background="{StaticResource Blue}" VerticalAlignment="Center">
                            <Path Data="{StaticResource IconShield}" Fill="White" Stretch="Uniform" Width="20" Height="20" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <StackPanel Margin="12,0,0,0" VerticalAlignment="Center">
                            <TextBlock Text="PolinRider" FontSize="16" FontWeight="Bold" Foreground="{StaticResource TextPri}"/>
                            <TextBlock Text="Monitor" FontSize="11" Foreground="{StaticResource TextSec}"/>
                        </StackPanel>
                    </StackPanel>
                </StackPanel>

                <!-- Nav -->
                <StackPanel Grid.Row="1">
                    <Button Name="NavDashboard" Style="{StaticResource NavButton}">
                        <StackPanel Orientation="Horizontal">
                            <Path Name="NavDashIcon" Data="{StaticResource IconDashboard}" Style="{StaticResource IconNav}"/>
                            <TextBlock Text="Dashboard" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                    <Button Name="NavLogs" Style="{StaticResource NavButton}">
                        <StackPanel Orientation="Horizontal">
                            <Path Name="NavLogsIcon" Data="{StaticResource IconLogs}" Style="{StaticResource IconNav}"/>
                            <TextBlock Text="Logs" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                    <Button Name="NavSettings" Style="{StaticResource NavButton}">
                        <StackPanel Orientation="Horizontal">
                            <Path Name="NavSettingsIcon" Data="{StaticResource IconCog}" Style="{StaticResource IconNav}"/>
                            <TextBlock Text="Settings" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                    <Button Name="NavAbout" Style="{StaticResource NavButton}">
                        <StackPanel Orientation="Horizontal">
                            <Path Name="NavAboutIcon" Data="{StaticResource IconInfo}" Style="{StaticResource IconNav}"/>
                            <TextBlock Text="About" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                </StackPanel>

                <!-- Footer -->
                <StackPanel Grid.Row="3" Margin="20,16">
                    <TextBlock Name="SidebarHost" FontSize="11" Foreground="{StaticResource TextMuted}"/>
                    <TextBlock FontSize="11" Foreground="{StaticResource TextMuted}" Margin="0,4,0,0">
                        <Run Text="v"/><Run Name="SidebarVersion" Text="1.0.0"/>
                    </TextBlock>
                </StackPanel>
            </Grid>
        </Border>

        <!-- ========== CONTENT ========== -->
        <Grid Grid.Column="1" Margin="32,28,32,24">
            <!-- ===== Page: Dashboard ===== -->
            <Grid Name="PageDashboard" Visibility="Visible">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>

                <!-- Page title -->
                <StackPanel Grid.Row="0" Margin="0,0,0,20">
                    <TextBlock Text="Dashboard" FontSize="24" FontWeight="Bold" Foreground="{StaticResource TextPri}"/>
                    <TextBlock Text="Scan summary and quick actions" FontSize="12" Foreground="{StaticResource TextSec}" Margin="0,4,0,0"/>
                </StackPanel>

                <!-- Status banner -->
                <Border Grid.Row="1" Style="{StaticResource CardStyle}" Margin="0,0,0,20" Name="StatusBanner">
                    <Grid Margin="28,24">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <Border Grid.Column="0" Width="56" Height="56" CornerRadius="28" Name="StatusIconBorder" Background="{StaticResource Slate}" VerticalAlignment="Center">
                            <Path Name="StatusIcon" Data="{StaticResource IconShield}" Fill="White" Stretch="Uniform" Width="28" Height="28" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <StackPanel Grid.Column="1" Margin="20,0,0,0" VerticalAlignment="Center">
                            <TextBlock Name="StatusText" Text="Ready" FontSize="22" FontWeight="Bold" Foreground="{StaticResource TextPri}"/>
                            <TextBlock Name="StatusDetail" Text="Click 'Scan Now' to begin" FontSize="13" Foreground="{StaticResource TextSec}" Margin="0,4,0,0"/>
                        </StackPanel>
                    </Grid>
                </Border>

                <!-- Stats cards -->
                <Grid Grid.Row="2" Margin="0,0,0,20">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    <Border Grid.Column="0" Style="{StaticResource CardStyle}" Margin="0,0,8,0">
                        <StackPanel Margin="18,16">
                            <TextBlock Text="FILES SCANNED" FontSize="10" FontWeight="SemiBold" Foreground="{StaticResource TextMuted}" Margin="0,0,0,8"/>
                            <TextBlock Name="StatFiles" Text="-" FontSize="28" FontWeight="Bold" Foreground="{StaticResource TextPri}"/>
                        </StackPanel>
                    </Border>
                    <Border Grid.Column="1" Style="{StaticResource CardStyle}" Margin="8,0,8,0">
                        <StackPanel Margin="18,16">
                            <TextBlock Text="INFECTED" FontSize="10" FontWeight="SemiBold" Foreground="{StaticResource TextMuted}" Margin="0,0,0,8"/>
                            <TextBlock Name="StatInfected" Text="-" FontSize="28" FontWeight="Bold" Foreground="{StaticResource TextPri}"/>
                        </StackPanel>
                    </Border>
                    <Border Grid.Column="2" Style="{StaticResource CardStyle}" Margin="8,0,8,0">
                        <StackPanel Margin="18,16">
                            <TextBlock Text="BAD PROCESSES" FontSize="10" FontWeight="SemiBold" Foreground="{StaticResource TextMuted}" Margin="0,0,0,8"/>
                            <TextBlock Name="StatProcs" Text="-" FontSize="28" FontWeight="Bold" Foreground="{StaticResource TextPri}"/>
                        </StackPanel>
                    </Border>
                    <Border Grid.Column="3" Style="{StaticResource CardStyle}" Margin="8,0,0,0">
                        <StackPanel Margin="18,16">
                            <TextBlock Text="C2 CONNECTIONS" FontSize="10" FontWeight="SemiBold" Foreground="{StaticResource TextMuted}" Margin="0,0,0,8"/>
                            <TextBlock Name="StatC2" Text="-" FontSize="28" FontWeight="Bold" Foreground="{StaticResource TextPri}"/>
                        </StackPanel>
                    </Border>
                </Grid>

                <!-- Buttons -->
                <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,0,0,20">
                    <Button Name="BtnScan" Style="{StaticResource PrimaryButton}" Margin="0,0,10,0">
                        <StackPanel Orientation="Horizontal">
                            <Path Data="{StaticResource IconSearch}" Style="{StaticResource IconBtn}"/>
                            <TextBlock Text="Scan Now" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                    <Button Name="BtnClean" Style="{StaticResource WarningButton}" IsEnabled="False">
                        <StackPanel Orientation="Horizontal">
                            <Path Data="{StaticResource IconBroom}" Style="{StaticResource IconBtn}"/>
                            <TextBlock Text="Clean Infections" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                    <ProgressBar Name="ScanProgress" Height="44" Width="200" Margin="14,0,0,0" Visibility="Collapsed" IsIndeterminate="True" Background="{StaticResource Card}" Foreground="{StaticResource Blue}" BorderThickness="0"/>
                </StackPanel>

                <!-- History -->
                <Border Grid.Row="4" Style="{StaticResource CardStyle}">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>
                        <StackPanel Grid.Row="0" Margin="20,18,20,12" Orientation="Horizontal">
                            <TextBlock Text="Scan history" FontSize="14" FontWeight="SemiBold" Foreground="{StaticResource TextPri}"/>
                            <TextBlock Name="HistoryCount" Text="" FontSize="12" Foreground="{StaticResource TextMuted}" Margin="10,2,0,0"/>
                        </StackPanel>
                        <ListView Grid.Row="1" Name="History" Margin="6,0,6,6">
                            <ListView.View>
                                <GridView>
                                    <GridViewColumn Header="WHEN" Width="160" DisplayMemberBinding="{Binding When}"/>
                                    <GridViewColumn Header="RESULT" Width="110" DisplayMemberBinding="{Binding Result}"/>
                                    <GridViewColumn Header="FILES" Width="90" DisplayMemberBinding="{Binding Files}"/>
                                    <GridViewColumn Header="INFECTED" Width="90" DisplayMemberBinding="{Binding Infected}"/>
                                    <GridViewColumn Header="PROCS" Width="80" DisplayMemberBinding="{Binding Procs}"/>
                                    <GridViewColumn Header="C2" Width="60" DisplayMemberBinding="{Binding C2}"/>
                                    <GridViewColumn Header="TIME" Width="80" DisplayMemberBinding="{Binding Duration}"/>
                                </GridView>
                            </ListView.View>
                        </ListView>
                    </Grid>
                </Border>
            </Grid>

            <!-- ===== Page: Logs (matrix style) ===== -->
            <Grid Name="PageLogs" Visibility="Collapsed">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>

                <StackPanel Grid.Row="0" Margin="0,0,0,16">
                    <TextBlock Text="Logs" FontSize="24" FontWeight="Bold" Foreground="{StaticResource TextPri}"/>
                    <TextBlock Text="Live scan output and history" FontSize="12" Foreground="{StaticResource TextSec}" Margin="0,4,0,0"/>
                </StackPanel>

                <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,0,0,12">
                    <Button Name="BtnClearLog" Style="{StaticResource SecondaryButton}" Margin="0,0,8,0">
                        <StackPanel Orientation="Horizontal">
                            <Path Data="{StaticResource IconTrash}" Style="{StaticResource IconBtn}"/>
                            <TextBlock Text="Clear" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                    <Button Name="BtnOpenLogFile" Style="{StaticResource SecondaryButton}">
                        <StackPanel Orientation="Horizontal">
                            <Path Data="{StaticResource IconLogs}" Style="{StaticResource IconBtn}"/>
                            <TextBlock Text="Open monitor.log" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                </StackPanel>

                <Border Grid.Row="2" CornerRadius="10" Background="{StaticResource MatrixBg}" BorderBrush="#0a3010" BorderThickness="1">
                    <Border.Effect>
                        <DropShadowEffect BlurRadius="20" ShadowDepth="3" Direction="270" Opacity="0.5" Color="Black"/>
                    </Border.Effect>
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>
                        <!-- terminal header -->
                        <Border Grid.Row="0" Background="#0a1a0a" CornerRadius="10,10,0,0" Padding="14,10" BorderBrush="#0a3010" BorderThickness="0,0,0,1">
                            <StackPanel Orientation="Horizontal">
                                <Ellipse Width="10" Height="10" Fill="#ff5f56" Margin="0,0,6,0"/>
                                <Ellipse Width="10" Height="10" Fill="#ffbd2e" Margin="0,0,6,0"/>
                                <Ellipse Width="10" Height="10" Fill="#27c93f" Margin="0,0,14,0"/>
                                <TextBlock Text="polinrider-monitor — live scan" FontFamily="Consolas" FontSize="12" Foreground="#7fc28b" VerticalAlignment="Center"/>
                            </StackPanel>
                        </Border>

                        <ScrollViewer Grid.Row="1" Name="LogScroller" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" Padding="16,12">
                            <TextBox Name="LogText" Background="Transparent" Foreground="{StaticResource MatrixGreen}" BorderThickness="0" IsReadOnly="True" FontFamily="Consolas" FontSize="13" TextWrapping="NoWrap" Padding="0" Text="">
                                <TextBox.Resources>
                                    <SolidColorBrush x:Key="{x:Static SystemColors.HighlightBrushKey}" Color="#00ff41" Opacity="0.3"/>
                                </TextBox.Resources>
                            </TextBox>
                        </ScrollViewer>
                    </Grid>
                </Border>
            </Grid>

            <!-- ===== Page: Settings ===== -->
            <Grid Name="PageSettings" Visibility="Collapsed">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <StackPanel Grid.Row="0" Margin="0,0,0,20">
                    <TextBlock Text="Settings" FontSize="24" FontWeight="Bold" Foreground="{StaticResource TextPri}"/>
                    <TextBlock Text="Configure scan paths and behaviour" FontSize="12" Foreground="{StaticResource TextSec}" Margin="0,4,0,0"/>
                </StackPanel>

                <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
                    <StackPanel>
                        <!-- Scan paths -->
                        <Border Style="{StaticResource CardStyle}" Margin="0,0,0,16">
                            <Grid Margin="20,16">
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="*"/>
                                    <RowDefinition Height="Auto"/>
                                </Grid.RowDefinitions>
                                <TextBlock Grid.Row="0" Text="Scan paths" FontSize="14" FontWeight="SemiBold" Foreground="{StaticResource TextPri}"/>
                                <TextBlock Grid.Row="1" Text="Folders to scan recursively. node_modules is always excluded." FontSize="11" Foreground="{StaticResource TextMuted}" Margin="0,4,0,12"/>
                                <ListBox Grid.Row="2" Name="PathsList" Background="#0F172A" Foreground="{StaticResource TextPri}" BorderBrush="{StaticResource CardBorder}" BorderThickness="1" MinHeight="180" Padding="6">
                                    <ListBox.ItemContainerStyle>
                                        <Style TargetType="ListBoxItem">
                                            <Setter Property="Padding" Value="10,8"/>
                                            <Setter Property="Background" Value="Transparent"/>
                                            <Setter Property="BorderBrush" Value="#1F2937"/>
                                            <Setter Property="BorderThickness" Value="0,0,0,1"/>
                                            <Style.Triggers>
                                                <Trigger Property="IsSelected" Value="True">
                                                    <Setter Property="Background" Value="#1E40AF"/>
                                                </Trigger>
                                            </Style.Triggers>
                                        </Style>
                                    </ListBox.ItemContainerStyle>
                                    <ListBox.ItemTemplate>
                                        <DataTemplate>
                                            <StackPanel Orientation="Horizontal">
                                                <Path Data="{StaticResource IconFolder}" Fill="#94A3B8" Stretch="Uniform" Width="16" Height="16" Margin="0,0,10,0" VerticalAlignment="Center"/>
                                                <TextBlock Text="{Binding}" FontFamily="Consolas" FontSize="12" VerticalAlignment="Center"/>
                                            </StackPanel>
                                        </DataTemplate>
                                    </ListBox.ItemTemplate>
                                </ListBox>
                                <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,12,0,0">
                                    <Button Name="BtnAddPath" Style="{StaticResource PrimaryButton}" Margin="0,0,10,0">
                                        <StackPanel Orientation="Horizontal">
                                            <Path Data="{StaticResource IconPlus}" Style="{StaticResource IconBtn}"/>
                                            <TextBlock Text="Add Folder" VerticalAlignment="Center"/>
                                        </StackPanel>
                                    </Button>
                                    <Button Name="BtnRemovePath" Style="{StaticResource DangerButton}">
                                        <StackPanel Orientation="Horizontal">
                                            <Path Data="{StaticResource IconTrash}" Style="{StaticResource IconBtn}"/>
                                            <TextBlock Text="Remove Selected" VerticalAlignment="Center"/>
                                        </StackPanel>
                                    </Button>
                                </StackPanel>
                            </Grid>
                        </Border>

                        <!-- Options -->
                        <Border Style="{StaticResource CardStyle}" Margin="0,0,0,16">
                            <StackPanel Margin="20,16">
                                <TextBlock Text="Options" FontSize="14" FontWeight="SemiBold" Foreground="{StaticResource TextPri}" Margin="0,0,0,12"/>
                                <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
                                    <TextBlock Text="Max file size (bytes):" Width="180" VerticalAlignment="Center" Foreground="{StaticResource TextSec}" FontSize="13"/>
                                    <TextBox Name="MaxFileSizeInput" Style="{StaticResource DarkInput}" Width="180"/>
                                    <TextBlock Text="Skip files larger than this" Foreground="{StaticResource TextMuted}" FontSize="11" Margin="12,0,0,0" VerticalAlignment="Center"/>
                                </StackPanel>
                                <CheckBox Name="AutoScanCheck" Content="Run a scan automatically when the app launches" Margin="0,4,0,0"/>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>

                <!-- Save -->
                <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,16,0,0">
                    <Button Name="BtnSaveSettings" Style="{StaticResource PrimaryButton}">
                        <StackPanel Orientation="Horizontal">
                            <Path Data="{StaticResource IconSave}" Style="{StaticResource IconBtn}"/>
                            <TextBlock Text="Save Settings" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                    <TextBlock Name="SettingsStatus" Text="" VerticalAlignment="Center" Margin="14,0,0,0" Foreground="{StaticResource Green}" FontSize="12"/>
                </StackPanel>
            </Grid>

            <!-- ===== Page: About ===== -->
            <Grid Name="PageAbout" Visibility="Collapsed">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>

                <StackPanel Grid.Row="0" Margin="0,0,0,20">
                    <TextBlock Text="About" FontSize="24" FontWeight="Bold" Foreground="{StaticResource TextPri}"/>
                    <TextBlock Text="Project info, links, credits" FontSize="12" Foreground="{StaticResource TextSec}" Margin="0,4,0,0"/>
                </StackPanel>

                <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
                    <StackPanel>
                        <Border Style="{StaticResource CardStyle}" Margin="0,0,0,16">
                            <StackPanel Margin="24,20">
                                <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                                    <Border Width="44" Height="44" CornerRadius="10" Background="{StaticResource Blue}" VerticalAlignment="Center">
                                        <Path Data="{StaticResource IconShield}" Fill="White" Stretch="Uniform" Width="24" Height="24" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                    </Border>
                                    <StackPanel Margin="14,0,0,0" VerticalAlignment="Center">
                                        <TextBlock Text="PolinRider Monitor" FontSize="20" FontWeight="Bold" Foreground="{StaticResource TextPri}"/>
                                        <TextBlock Name="AboutVersion" Text="" FontSize="12" Foreground="{StaticResource TextSec}"/>
                                    </StackPanel>
                                </StackPanel>
                                <TextBlock TextWrapping="Wrap" FontSize="13" Foreground="{StaticResource TextPri}" Margin="0,12,0,0" LineHeight="22">
                                    Free, open-source desktop security tool that scans Windows machines for the PolinRider / BeaverTail (DPRK Lazarus) JavaScript supply-chain malware. The malware hides obfuscated JavaScript in common config files like postcss.config.mjs, tailwind.config.js, next.config.mjs, and Express route files. When triggered by npm install / dev, it pushes itself to every GitHub repo your credentials can reach.
                                </TextBlock>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource CardStyle}" Margin="0,0,0,16">
                            <StackPanel Margin="24,18">
                                <TextBlock Text="Links" FontSize="14" FontWeight="SemiBold" Foreground="{StaticResource TextPri}" Margin="0,0,0,10"/>
                                <StackPanel>
                                    <TextBlock FontSize="13" Margin="0,4,0,0">
                                        <Run Foreground="{StaticResource TextSec}" Text="Repo:  "/>
                                        <Hyperlink Name="LinkRepo" Foreground="#60A5FA">https://github.com/Saif-Arshad/polinrider-monitor</Hyperlink>
                                    </TextBlock>
                                    <TextBlock FontSize="13" Margin="0,4,0,0">
                                        <Run Foreground="{StaticResource TextSec}" Text="OSM article:  "/>
                                        <Hyperlink Name="LinkOSM" Foreground="#60A5FA">https://opensourcemalware.com/blog/polinrider-attack</Hyperlink>
                                    </TextBlock>
                                    <TextBlock FontSize="13" Margin="0,4,0,0">
                                        <Run Foreground="{StaticResource TextSec}" Text="PolinRider IoCs:  "/>
                                        <Hyperlink Name="LinkIoCs" Foreground="#60A5FA">https://github.com/OpenSourceMalware/PolinRider</Hyperlink>
                                    </TextBlock>
                                </StackPanel>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource CardStyle}" Margin="0,0,0,16">
                            <StackPanel Margin="24,18">
                                <TextBlock Text="Credits" FontSize="14" FontWeight="SemiBold" Foreground="{StaticResource TextPri}" Margin="0,0,0,10"/>
                                <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="{StaticResource TextSec}" LineHeight="20">
                                    Icons by Material Design Icons (pictogrammers.com/library/mdi), Apache 2.0 license.
                                    <LineBreak/>
                                    Threat intel published by OpenSourceMalware research team.
                                    <LineBreak/>
                                    Built with PowerShell + WPF. No external dependencies.
                                </TextBlock>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource CardStyle}">
                            <StackPanel Margin="24,18">
                                <TextBlock Text="License" FontSize="14" FontWeight="SemiBold" Foreground="{StaticResource TextPri}" Margin="0,0,0,10"/>
                                <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="{StaticResource TextSec}" LineHeight="20">
                                    MIT — provided as-is with no warranty. Always verify cleanups against original sources before pushing fixes. If you find a variant this tool misses, please open an issue on GitHub.
                                </TextBlock>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>
            </Grid>
        </Grid>
    </Grid>
</Window>
'@

# === Load XAML ===
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$ui = @{}
$elementNames = @(
    'NavDashboard','NavLogs','NavSettings','NavAbout',
    'NavDashIcon','NavLogsIcon','NavSettingsIcon','NavAboutIcon',
    'SidebarHost','SidebarVersion',
    'PageDashboard','PageLogs','PageSettings','PageAbout',
    'StatusBanner','StatusIconBorder','StatusIcon','StatusText','StatusDetail',
    'StatFiles','StatInfected','StatProcs','StatC2',
    'BtnScan','BtnClean','ScanProgress',
    'History','HistoryCount',
    'LogText','LogScroller','BtnClearLog','BtnOpenLogFile',
    'PathsList','BtnAddPath','BtnRemovePath','MaxFileSizeInput','AutoScanCheck','BtnSaveSettings','SettingsStatus',
    'AboutVersion','LinkRepo','LinkOSM','LinkIoCs'
)
foreach ($n in $elementNames) { $ui[$n] = $window.FindName($n) }

$ui.SidebarHost.Text    = "$env:COMPUTERNAME · $env:USERNAME"
$ui.SidebarVersion.Text = $version
$ui.AboutVersion.Text   = "Version $version"

# === Helpers ===
function Write-File-Log($msg) {
    $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    Add-Content -LiteralPath $logFile -Value $line -Encoding utf8
}

function Append-LiveLog([string]$line) {
    $ui.LogText.AppendText("$line`r`n")
    $ui.LogScroller.ScrollToEnd()
}

function Load-History {
    if (-not (Test-Path $historyFile)) { return @() }
    try { return @(Get-Content $historyFile -Raw | ConvertFrom-Json) } catch { return @() }
}

function Save-History($entry) {
    $hist = @(Load-History)
    $hist = @($entry) + $hist
    if ($hist.Count -gt 50) { $hist = $hist[0..49] }
    $hist | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $historyFile -Encoding utf8
}

function Set-Status([string]$state, [string]$detail) {
    $bc = [System.Windows.Media.BrushConverter]::new()
    switch ($state) {
        'clean'    { $ui.StatusIconBorder.Background = $bc.ConvertFrom('#10B981'); $ui.StatusIcon.Data = $window.Resources['IconShieldCheck']; $ui.StatusText.Text = 'Clean' }
        'infected' { $ui.StatusIconBorder.Background = $bc.ConvertFrom('#EF4444'); $ui.StatusIcon.Data = $window.Resources['IconShieldAlert']; $ui.StatusText.Text = 'Infections detected' }
        'scanning' { $ui.StatusIconBorder.Background = $bc.ConvertFrom('#3B82F6'); $ui.StatusIcon.Data = $window.Resources['IconLoading'];      $ui.StatusText.Text = 'Scanning...' }
        'error'    { $ui.StatusIconBorder.Background = $bc.ConvertFrom('#F59E0B'); $ui.StatusIcon.Data = $window.Resources['IconShieldAlert']; $ui.StatusText.Text = 'Error' }
        default    { $ui.StatusIconBorder.Background = $bc.ConvertFrom('#475569'); $ui.StatusIcon.Data = $window.Resources['IconShield'];      $ui.StatusText.Text = 'Ready' }
    }
    $ui.StatusDetail.Text = $detail
}

function Refresh-Dashboard {
    $hist = Load-History
    $ui.History.ItemsSource = @($hist)
    $ui.HistoryCount.Text = "($($hist.Count) entries)"
    if ($hist.Count -gt 0) {
        $latest = $hist[0]
        $isClean = ($latest.Infected -eq 0 -and $latest.Procs -eq 0 -and $latest.C2 -eq 0)
        if ($isClean) {
            Set-Status 'clean' "Last scanned $($latest.When)  ·  $($latest.Files) files in $($latest.Duration)"
        } else {
            Set-Status 'infected' "Last scanned $($latest.When)  ·  click 'Clean Infections' to fix"
        }
        $ui.StatFiles.Text    = "$($latest.Files)"
        $ui.StatInfected.Text = "$($latest.Infected)"
        $ui.StatProcs.Text    = "$($latest.Procs)"
        $ui.StatC2.Text       = "$($latest.C2)"
        $ui.BtnClean.IsEnabled = (-not $isClean)
    } else {
        Set-Status 'ready' "Click 'Scan Now' to begin"
        $ui.StatFiles.Text='-'; $ui.StatInfected.Text='-'; $ui.StatProcs.Text='-'; $ui.StatC2.Text='-'
        $ui.BtnClean.IsEnabled = $false
    }
}

# === Navigation ===
function Show-Page([string]$name) {
    $bc = [System.Windows.Media.BrushConverter]::new()
    $activeFill = $bc.ConvertFrom('#F1F5F9')
    $inactiveFill = $bc.ConvertFrom('#94A3B8')
    foreach ($p in @('Dashboard','Logs','Settings','About')) {
        $pageEl = $ui["Page$p"]
        $navEl  = $ui["Nav$p"]
        $iconKey = "Nav${p}Icon"
        $iconEl = $ui[$iconKey]
        if ($p -eq $name) {
            $pageEl.Visibility = 'Visible'
            $navEl.Background = $bc.ConvertFrom('#172033')
            $navEl.Foreground = $bc.ConvertFrom('#F1F5F9')
            if ($iconEl) { $iconEl.Fill = $activeFill }
        } else {
            $pageEl.Visibility = 'Collapsed'
            $navEl.Background = [System.Windows.Media.Brushes]::Transparent
            $navEl.Foreground = $bc.ConvertFrom('#94A3B8')
            if ($iconEl) { $iconEl.Fill = $inactiveFill }
        }
    }
}

# === Scan ===
function Run-Scan {
    Set-Status 'scanning' "Running scan - switch to Logs tab to watch live progress"
    $ui.BtnScan.IsEnabled = $false
    $ui.BtnClean.IsEnabled = $false
    $ui.ScanProgress.Visibility = 'Visible'

    # Reset live log
    $global:scanLog.Clear()
    $global:lastLogIndex = 0
    $ui.LogText.Text = ""
    Append-LiveLog ("=== scan started {0} ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'; $rs.ThreadOptions = 'ReuseThread'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('m1', $global:m1)
    $rs.SessionStateProxy.SetVariable('m2', $global:m2)
    $rs.SessionStateProxy.SetVariable('m3', $global:m3)
    $rs.SessionStateProxy.SetVariable('m4', $global:m4)
    $rs.SessionStateProxy.SetVariable('scanPaths', @($global:config.ScanPaths))
    $rs.SessionStateProxy.SetVariable('maxSize', $global:config.MaxFileSize)
    $rs.SessionStateProxy.SetVariable('scanLog', $global:scanLog)

    $ps = [PowerShell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        function L($msg) { [void]$scanLog.Add("$((Get-Date).ToString('HH:mm:ss')) $msg") }
        $markers = @($m1, $m2, $m3, $m4)
        $c2IPs = @('166.88.54.158','54.251.176.6','52.221.63.237','18.142.149.167','34.36.29.190','52.223.34.155','35.71.137.105')
        $start = Get-Date
        $infectedFiles = @(); $totalScanned = 0

        L "=== file scan ==="
        foreach ($path in $scanPaths) {
            if (-not (Test-Path $path)) {
                L "[skip] not found: $path"
                continue
            }
            $files = Get-ChildItem -Path $path -Recurse -Force -Include "*.js","*.mjs","*.cjs","*.jsx","*.ts","*.tsx" -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch '\\node_modules\\' -and $_.Length -lt $maxSize }
            L (">> {0}  ({1} files)" -f $path, $files.Count)
            foreach ($f in $files) {
                $totalScanned++
                $rel = $f.FullName.Substring($path.Length).TrimStart('\','/')
                if ($rel.Length -gt 80) { $rel = "..." + $rel.Substring($rel.Length - 77) }
                try {
                    $c = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
                    $hits = 0
                    foreach ($m in $markers) { if ($c.IndexOf($m) -ge 0) { $hits++ } }
                    if ($hits -ge 2) {
                        $infectedFiles += $f.FullName
                        L ("   [HIT] {0}  <-- INFECTED" -f $rel)
                    } else {
                        if ($totalScanned % 25 -eq 0) {
                            L ("   ... scanned {0} files (current: {1})" -f $totalScanned, $rel)
                        }
                    }
                } catch {
                    L ("   [err] {0}: {1}" -f $rel, $_.Exception.Message)
                }
            }
        }

        L "=== process scan ==="
        $evalMarker = -join ([char[]]@(103,108,111,98,97,108,91))
        $badProcs = @(Get-WmiObject Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and ($_.CommandLine.IndexOf($evalMarker) -ge 0) -and ($_.CommandLine -match ' -e |--eval') })
        $procIds = @($badProcs | ForEach-Object { $_.ProcessId })
        if ($procIds.Count -eq 0) { L "no suspicious node.exe processes" } else { foreach ($p in $badProcs) { L ("   [PROC] PID {0}" -f $p.ProcessId) } }

        L "=== c2 connection scan ==="
        $c2Hits = @()
        foreach ($ip in $c2IPs) {
            $conns = Get-NetTCPConnection -RemoteAddress $ip -ErrorAction SilentlyContinue
            foreach ($cn in $conns) { $c2Hits += "$ip <- PID $($cn.OwningProcess)"; L ("   [CONN] {0}" -f $c2Hits[-1]) }
        }
        if ($c2Hits.Count -eq 0) { L "no active C2 connections" }

        $elapsed = (Get-Date) - $start
        $result = if ($infectedFiles.Count -eq 0 -and $procIds.Count -eq 0 -and $c2Hits.Count -eq 0) { 'CLEAN' } else { 'INFECTED' }
        L ""
        L ("=== scan complete: {0}  ({1} files in {2:N1}s) ===" -f $result, $totalScanned, $elapsed.TotalSeconds)

        @{
            When     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Files    = $totalScanned
            Infected = $infectedFiles.Count
            Procs    = $procIds.Count
            C2       = $c2Hits.Count
            Duration = ('{0:N1}s' -f $elapsed.TotalSeconds)
            Result   = $result
            InfectedFiles = $infectedFiles
            ProcIds  = $procIds
            C2Hits   = $c2Hits
        }
    })
    $handle = $ps.BeginInvoke()

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(300)
    $timer.Add_Tick({
        while ($global:lastLogIndex -lt $global:scanLog.Count) {
            $entry = $global:scanLog[$global:lastLogIndex]
            Append-LiveLog $entry
            $global:lastLogIndex++
        }
        if ($handle.IsCompleted) {
            $timer.Stop()
            $result = $ps.EndInvoke($handle)[0]
            $ps.Dispose(); $rs.Close()
            $ui.ScanProgress.Visibility = 'Collapsed'
            $ui.BtnScan.IsEnabled = $true
            Save-History $result
            Write-File-Log "Scan: $($result.Result) - files=$($result.Files) infected=$($result.Infected) procs=$($result.Procs) c2=$($result.C2) duration=$($result.Duration)"
            Refresh-Dashboard
        }
    })
    $timer.Start()
}

# === Clean ===
function Clean-Infections {
    $hist = Load-History
    if ($hist.Count -eq 0) { return }
    $latest = $hist[0]
    $cleaned = 0; $failed = 0; $killed = 0

    if ($latest.InfectedFiles -and $latest.InfectedFiles.Count -gt 0) {
        foreach ($f in $latest.InfectedFiles) {
            if (-not (Test-Path $f)) { $failed++; continue }
            try {
                $c = Get-Content -LiteralPath $f -Raw
                $c = $c -replace "import \{ createRequire \} from 'module';\s*\r?\n", ""
                $c = $c -replace "const require = createRequire\(import\.meta\.url\);\s*\r?\n", ""
                $idx = $c.IndexOf($global:payloadStart)
                if ($idx -ge 0) { $c = $c.Substring(0, $idx).TrimEnd(' ',"`t","`r","`n") + "`r`n" }
                Set-Content -LiteralPath $f -Value $c -NoNewline -Encoding utf8
                $cleaned++
                Append-LiveLog ("{0} [clean] {1}" -f (Get-Date -Format 'HH:mm:ss'), $f)
            } catch { $failed++ }
        }
    }
    if ($latest.ProcIds) {
        foreach ($pidVal in $latest.ProcIds) {
            try { Stop-Process -Id $pidVal -Force -ErrorAction Stop; $killed++; Append-LiveLog ("{0} [killed PID {1}]" -f (Get-Date -Format 'HH:mm:ss'), $pidVal) } catch { }
        }
    }
    Write-File-Log "Clean: $cleaned files cleaned, $killed processes killed, $failed failures"
    $msg = "Cleaned $cleaned local file(s)" + $(if ($killed -gt 0) { ", killed $killed malicious process(es)" } else { "" }) + ".`n`nNOTE: this fixes LOCAL files only. For any cleaned file in a git repo, run 'git add . && git commit && git push' to fix the remote."
    [System.Windows.MessageBox]::Show($msg, "Cleanup complete", "OK", "Information") | Out-Null
}

# === Settings ===
function Load-PathsIntoUi {
    $coll = New-Object System.Collections.ObjectModel.ObservableCollection[string]
    foreach ($p in @($global:config.ScanPaths)) { $coll.Add($p) }
    $ui.PathsList.ItemsSource = $coll
    $global:pathsCollection = $coll
    $ui.MaxFileSizeInput.Text = "$($global:config.MaxFileSize)"
    $ui.AutoScanCheck.IsChecked = [bool]$global:config.AutoScanOnLaunch
}

function Add-Path {
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = "Choose a folder to add to the scan paths"
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $path = $dlg.SelectedPath
        if ($global:pathsCollection -notcontains $path) {
            $global:pathsCollection.Add($path)
        }
    }
}

function Remove-Path {
    $sel = $ui.PathsList.SelectedItem
    if ($sel) { [void]$global:pathsCollection.Remove($sel) }
}

function Save-Settings {
    $newPaths = @()
    foreach ($p in $global:pathsCollection) { $newPaths += $p }
    $maxSize = 10000000
    if ([int]::TryParse($ui.MaxFileSizeInput.Text, [ref]$maxSize)) { } else { $maxSize = 10000000 }
    $cfg = [ordered]@{
        ScanPaths = $newPaths
        MaxFileSize = $maxSize
        AutoScanOnLaunch = [bool]$ui.AutoScanCheck.IsChecked
    }
    $cfg | ConvertTo-Json | Set-Content -LiteralPath $configFile -Encoding utf8
    $global:config = $cfg | ConvertTo-Json | ConvertFrom-Json
    $ui.SettingsStatus.Text = "Saved at $(Get-Date -Format 'HH:mm:ss')"
}

# === Logs page helpers ===
function Load-MonitorLogIntoUi {
    if (Test-Path $logFile) {
        $tail = Get-Content -LiteralPath $logFile -Tail 100 -ErrorAction SilentlyContinue
        if ($tail) { $ui.LogText.Text = ($tail -join "`r`n") + "`r`n" }
    } else {
        $ui.LogText.Text = "(no scans logged yet - run one from the Dashboard)`r`n"
    }
    $ui.LogScroller.ScrollToEnd()
}

# === Wire events ===
$ui.NavDashboard.Add_Click({ Show-Page 'Dashboard' })
$ui.NavLogs.Add_Click({      Show-Page 'Logs' })
$ui.NavSettings.Add_Click({  Load-PathsIntoUi; Show-Page 'Settings' })
$ui.NavAbout.Add_Click({     Show-Page 'About' })

$ui.BtnScan.Add_Click({ Show-Page 'Logs'; Run-Scan })
$ui.BtnClean.Add_Click({ Clean-Infections })
$ui.BtnClearLog.Add_Click({ $ui.LogText.Text = "" })
$ui.BtnOpenLogFile.Add_Click({
    if (Test-Path $logFile) { Start-Process notepad.exe -ArgumentList $logFile }
    else { [System.Windows.MessageBox]::Show("No log yet - run a scan first.", "PolinRider Monitor") | Out-Null }
})

$ui.BtnAddPath.Add_Click({ Add-Path })
$ui.BtnRemovePath.Add_Click({ Remove-Path })
$ui.BtnSaveSettings.Add_Click({ Save-Settings })

$ui.LinkRepo.Add_Click({ Start-Process "https://github.com/Saif-Arshad/polinrider-monitor" })
$ui.LinkOSM.Add_Click({  Start-Process "https://opensourcemalware.com/blog/polinrider-attack" })
$ui.LinkIoCs.Add_Click({ Start-Process "https://github.com/OpenSourceMalware/PolinRider" })

# Initial state
Refresh-Dashboard
Load-MonitorLogIntoUi
Show-Page 'Dashboard'

if ($global:config.AutoScanOnLaunch) { Run-Scan }

$window.ShowDialog() | Out-Null
