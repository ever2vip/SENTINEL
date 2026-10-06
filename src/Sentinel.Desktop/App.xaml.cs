using System.Windows;

namespace Sentinel.Desktop;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
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
