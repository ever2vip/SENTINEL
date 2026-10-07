using System.Windows;

namespace Sentinel.Desktop;

public partial class App : Application
{
    // The installed-assembly acceptance host creates its own explicitly isolated
    // MainWindow. Application schedules OnStartup even when using Dispatcher.Run,
    // so the harness must opt out of opening the ordinary operator profile.
    // The production entry point leaves this false and follows normal startup.
    internal bool SuppressOperatorStartupForTesting { get; set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (SuppressOperatorStartupForTesting) return;
        DispatcherUnhandledException += (_, args) =>
        {
            args.Handled = true;
            if (MainWindow is MainWindow window) window.ShowFailure(args.Exception);
            else MessageBox.Show("SENTINEL could not start. Reopen the application or contact your administrator.", "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Error);
        };
        MainWindow = new MainWindow();
        MainWindow.Show();
    }
}
