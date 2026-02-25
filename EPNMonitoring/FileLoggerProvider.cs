using System;
using System.IO;
using Microsoft.Extensions.Logging;

namespace EPNMonitoring
{
    /// <summary>
    /// Simple logger provider that writes log messages to a single file.
    /// </summary>
    public sealed class FileLoggerProvider : ILoggerProvider
    {
        private readonly string _filePath;
        private readonly object _lock = new();
        private StreamWriter _writer;

        public FileLoggerProvider(string filePath)
        {
            _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
            var dir = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
            _writer = new StreamWriter(File.Open(_filePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
            {
                AutoFlush = true
            };
        }

        public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);

        /// <summary>
        /// Truncates the log file by rotating it and keeping the last 5 backup files.
        /// The current file is renamed to .001, previous .001 becomes .002, etc.
        /// The oldest file (.005) is deleted.
        /// </summary>
        public void TruncateLog()
        {
            lock (_lock)
            {
                _writer?.Dispose();

                // Rotate backup files (delete .005, rename .004 to .005, .003 to .004, etc.)
                const int maxBackups = 5;
                for (int i = maxBackups; i >= 1; i--)
                {
                    string sourceFile = i == 1 ? _filePath : $"{_filePath}.{i - 1:D3}";
                    string targetFile = $"{_filePath}.{i:D3}";

                    if (i == maxBackups && File.Exists(targetFile))
                    {
                        File.Delete(targetFile);
                    }

                    if (File.Exists(sourceFile))
                    {
                        File.Move(sourceFile, targetFile, overwrite: true);
                    }
                }

                // Create a new empty log file
                _writer = new StreamWriter(File.Open(_filePath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite))
                {
                    AutoFlush = true
                };
            }
        }

        internal void WriteLog(string line)
        {
            lock (_lock)
            {
                _writer?.WriteLine(line);
            }
        }

        public void Dispose() => _writer?.Dispose();

        private sealed class FileLogger : ILogger
        {
            private readonly FileLoggerProvider _provider;
            private readonly string _categoryName;

            public FileLogger(FileLoggerProvider provider, string categoryName)
            {
                _provider = provider;
                _categoryName = categoryName;
            }

            public IDisposable BeginScope<TState>(TState state) => null!;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                if (formatter == null) throw new ArgumentNullException(nameof(formatter));

                var message = formatter(state, exception);
                if (string.IsNullOrEmpty(message) && exception == null) return;

                var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                var line = $"{timestamp} [{logLevel}] {_categoryName}: {message}";
                if (exception != null)
                {
                    line += $" {exception}";
                }

                _provider.WriteLog(line);
            }
        }
    }
}
