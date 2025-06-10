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
        private readonly StreamWriter _writer;

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

        public ILogger CreateLogger(string categoryName) => new FileLogger(_writer, _lock, categoryName);

        public void Dispose() => _writer.Dispose();

        private sealed class FileLogger : ILogger
        {
            private readonly StreamWriter _writer;
            private readonly object _lock;
            private readonly string _categoryName;

            public FileLogger(StreamWriter writer, object lockObj, string categoryName)
            {
                _writer = writer;
                _lock = lockObj;
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

                lock (_lock)
                {
                    _writer.WriteLine(line);
                }
            }
        }
    }
}
