namespace Dhcpr.Core;

public interface IValidateSelf
{
    /// <summary>
    /// Returns <see langword="true"/> when this instance's values are valid.
    /// </summary>
    bool Validate();
}