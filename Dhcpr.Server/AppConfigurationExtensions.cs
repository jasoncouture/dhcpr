namespace Dhcpr.Server;

public static class AppConfigurationExtensions
{
    private const string UnixLikeOSConfigurationPath = "/etc/dhcpr";
    private const string NonUnixOSConfigurationPath = @"dhcpr\configuration";
    private const string BaseConfigurationFileName = "configuration";
    private static readonly string UserBaseConfigurationFile = Path.ChangeExtension(BaseConfigurationFileName, "json");
    private const string MultipleFileFolderName = "conf.d";
    private const string MultipleFileSearchMask = "*.json";

    // Assume all non-ms platforms are unix like.
    // And this should never be anything but Win32NT, but you never know right?
    private static readonly HashSet<PlatformID> NonEtcPlatforms =
        new() { PlatformID.Xbox, PlatformID.Win32S, PlatformID.Win32Windows, PlatformID.Win32NT };

    private static readonly string DefaultBasePath = NonEtcPlatforms.Contains(Environment.OSVersion.Platform)
        ? NonUnixOSConfigurationPath
        : UnixLikeOSConfigurationPath;

    public static IConfigurationBuilder AddPlatformConfigurationLocations(this IConfigurationBuilder builder,
        string[]? args = null)
    {
        args ??= Environment.GetCommandLineArgs();
        var basePath = Path.GetFullPath(GetBasePath(DefaultBasePath, args));

        if (!Directory.Exists(basePath))
        {
            Console.WriteLine($"User configuration path {basePath} does not exist, trying to create it.");
            try
            {
                Directory.CreateDirectory(basePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Configuration path {basePath} could not be created.");
                Console.WriteLine(
                    "Configuration will not be loaded from here until it is manually created, and the application is restarted.");
                return builder;
            }

            Console.WriteLine("Configuration folder created successfully.");
        }


        var baseFile = Path.Combine(basePath, UserBaseConfigurationFile);
        builder.AddJsonFile(baseFile, optional: true, reloadOnChange: true);
        Console.WriteLine($"Added optional file {baseFile}");
        // This allows having a configuration in say, git. but each machine will load it's own config too.
        var hostFile = Path.ChangeExtension(baseFile, $"{Environment.MachineName.ToLower()}.json");
        builder.AddJsonFile(hostFile, optional: true, reloadOnChange: true);
        Console.WriteLine($"Added optional file {hostFile}");

        builder.AddSharedConfigurationFiles(basePath);
        builder.AddHostConfigurationDirectory(basePath);

        Console.WriteLine(
            "Added files, any additional files added to the directory will require an application restart to load.");
        Console.WriteLine("Changes to added files will be respected.");
        return builder;
    }

    private static IConfigurationBuilder AddMultipleConfigurationFiles(this IConfigurationBuilder builder, string path)
    {
        if (!Directory.Exists(path))
            return builder;

        foreach (var file in Directory.EnumerateFiles(path,
                     MultipleFileSearchMask,
                     SearchOption.AllDirectories))
        {
            builder.AddJsonFile(file, optional: true, reloadOnChange: true);
            Console.WriteLine($"Added optional file {file}");
        }

        return builder;
    }

    private static IConfigurationBuilder AddHostConfigurationDirectory(this IConfigurationBuilder builder,
        string basePath)
    {
        var hostConfigurationFolder = Path.Combine(basePath, $"conf.{Environment.MachineName.ToLower()}.d");
        return builder.AddMultipleConfigurationFiles(hostConfigurationFolder);
    }

    private static IConfigurationBuilder AddSharedConfigurationFiles(this IConfigurationBuilder builder,
        string basePath)
        => builder.AddMultipleConfigurationFiles(Path.Combine(basePath, MultipleFileFolderName));

    private static string GetBasePath(string defaultBasePath, string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine($"Using platform default user configuration path: {defaultBasePath}");
            return defaultBasePath;
        }

        var possibleArgs = args.Where(i => i.StartsWith("--configuration-directory=")).ToArray();

        if (possibleArgs.Length == 1)
        {
            // This won't throw, because we know that we have an =, and we only take 2 parts.
            // If it's not a valid path, we'll throw later.
            var configurationDirectoryOverride = possibleArgs[0].Split('=', 2)[1];
            Console.WriteLine(
                $"Using command line specified configuration path: {configurationDirectoryOverride}");
            return configurationDirectoryOverride;
        }

        throw new InvalidOperationException(
            "Multiple configuration directories specified. Only one directory can be configured.");
    }
}