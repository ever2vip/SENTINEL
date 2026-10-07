using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace Sentinel.Desktop;

/// <summary>Visible, user-controlled tray status. Never schedules collection or keeps the app alive after close.</summary>
internal sealed class TrayNotifications : IDisposable
{
    private const int Callback = 0x8001;
    private readonly Window _window;
    private readonly Action _openChanges;
    private readonly HwndSource? _source;
    private NotifyIconData _data;
    private bool _registered;
    public TrayNotifications(Window window, Action openChanges)
    {
        _window = window; _openChanges = openChanges;
        var handle = new WindowInteropHelper(window).Handle;
        _source = HwndSource.FromHwnd(handle);
        _data = new NotifyIconData { Size = (uint)Marshal.SizeOf<NotifyIconData>(), Window = handle, Id = 1, Flags = 1 | 2 | 4, Callback = Callback, Tip = "SENTINEL Enterprise · On-demand assessments", Info = "", InfoTitle = "" };
        _data.Icon = ExtractIconW(0, Environment.ProcessPath ?? "", 0);
        if (_data.Icon == 0 || _data.Icon == 1) return;
        _source?.AddHook(Hook);
        _registered = Shell_NotifyIconW(0, ref _data);
    }
    public void Notify(string title, string evidence)
    {
        if (!_registered) return;
        _data.Flags = 16;
        _data.InfoTitle = title.Length > 63 ? title[..63] : title;
        _data.Info = evidence.Length > 255 ? evidence[..255] : evidence;
        _data.InfoFlags = 2;
        Shell_NotifyIconW(1, ref _data);
    }
    private nint Hook(nint hwnd, int message, nint wp, nint lp, ref bool handled)
    {
        if (message != Callback) return 0;
        var action = (int)(lp.ToInt64() & 0xffff);
        if (action is 0x0203 or 0x0405) // Double click or balloon selected.
        {
            _window.Show(); _window.WindowState = WindowState.Normal; _window.Activate();
            if (action == 0x0405) _openChanges();
            handled = true;
        }
        return 0;
    }
    public void Dispose()
    {
        if (_registered) { Shell_NotifyIconW(2, ref _data); _registered = false; }
        _source?.RemoveHook(Hook);
        if (_data.Icon != 0 && _data.Icon != 1) { DestroyIcon(_data.Icon); _data.Icon = 0; }
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public uint Size; public nint Window; public uint Id; public uint Flags; public int Callback; public nint Icon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Tip;
        public uint State; public uint StateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Info;
        public uint Version;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string InfoTitle;
        public uint InfoFlags; public Guid Guid; public nint BalloonIcon;
    }
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool Shell_NotifyIconW(uint message, ref NotifyIconData data);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern nint ExtractIconW(nint instance, string file, uint index);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DestroyIcon(nint icon);
}
