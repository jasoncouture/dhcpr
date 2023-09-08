using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Peering.Discovery.UnitTests;

[SuppressMessage("ReSharper", "ClassCanBeSealed.Global")]
public class MulticastConfigurationTests
{
    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("240.0.0.0")]
    [InlineData("0.0.0.0:-1")]
    [InlineData("0.0.0.0:a")]
    public void ValidationFailsWhenAddressIsNotMulticast(string addressOrEndPoint)
    {
        var config = new MulticastConfiguration() { Address = addressOrEndPoint };

        Assert.False(config.Validate());
    }

    [Theory]
    [MemberData(nameof(GenerateMulticastAddresses))]
    public void ValidationPassesWhenValidMulticastAddressIsProvided(string addressOrEndPoint)
    {
        var config = new MulticastConfiguration() { Address = addressOrEndPoint };
        Assert.True(config.Validate());
    }

    public static IEnumerable<object[]> GenerateMulticastAddresses()
    {
        for (var firstOctet = 224; firstOctet <= 239; firstOctet++)
        {
            for (var secondOctet = 0; secondOctet <= 255; secondOctet++)
            {
                yield return new object[]
                {
                    $"{firstOctet}.{secondOctet}.{secondOctet}.{secondOctet}"
                };

                yield return new object[]
                {
                    $"{firstOctet}.{secondOctet}.{secondOctet}.{secondOctet}:1234"
                };
            }
        }
    }
}