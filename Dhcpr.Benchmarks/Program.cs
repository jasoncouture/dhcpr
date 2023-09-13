// See https://aka.ms/new-console-template for more information


using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;


var config = DefaultConfig.Instance.WithOption(ConfigOptions.DisableOptimizationsValidator, true);

BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args, config);
