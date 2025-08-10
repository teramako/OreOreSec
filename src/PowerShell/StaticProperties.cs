using System.Management.Automation;
using System.Reflection;

namespace MT.PowerShell;

/// <summary>
/// PowerShell <see cref="ValidateSetAttribute"/>  属性と共に使用し、<typeparamref name="T"/> のstaticプロパティ名であることを検証する
/// </summary>
/// <remarks>
/// 例:
/// <example>
/// <code>
/// param(
///   [Parameter()]
///   [ValidateSet([MT.PowerShell.Completer.StaticProperties[HashAlgorithmName]])]
///   [string] $HashAlgorithm = 'SHA256'
/// )
/// </code>
/// </example>
/// </remarks>
public class StaticProperties<T> : IValidateSetValuesGenerator
{
    public string[] GetValidValues()
    {
        var t = typeof(T);
        return [.. t.GetProperties(BindingFlags.Public | BindingFlags.Static | BindingFlags.GetProperty)
                     .Where(p => p.DeclaringType == t)
                     .Select(p => p.Name)];
    }
}
