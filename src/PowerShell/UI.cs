using System.Management.Automation.Host;
using System.Security;

namespace MT.PowerShell;

public static class UI
{
    /// <summary>
    /// パスワード入力プロンプトを出す。
    /// PowerShell の <c>Get-Credential</c> 等とは違い、ユーザー名値が不要。
    /// </summary>
    public static SecureString PasswordPrompt(PSHostUserInterface ui,
                                              string prompt = "Password",
                                              string caption = "",
                                              string message = "")
    {
        ArgumentException.ThrowIfNullOrEmpty(prompt);
        FieldDescription fd = new(prompt);
        fd.SetParameterType(typeof(SecureString));
        var response = ui.Prompt(caption, message, [fd]);
        var password = (SecureString)response[prompt].BaseObject;
        password.MakeReadOnly();
        return password;
    }

    /// <summary>
    /// 文字列のリストから選択プロンプトを出す。
    /// </summary>
    public static string ChoicePrompt(PSHostUserInterface ui,
                                      string[] labels,
                                      string caption = "",
                                      string message = "")
    {
        ChoiceDescription[] choices = new ChoiceDescription[labels.Length];
        for (var i = 0; i < labels.Length; i++)
        {
            choices[i] = new($"&{i + 1}.{labels[i]}", labels[i]);
        }
        var index = ui.PromptForChoice(caption, message, [.. choices], -1);
        return labels[index];
    }

    /// <summary>
    /// <typeparamref name="TEnum"/> 値の選択プロンプトを出す。
    /// 0 以下の値は選択対象から外れる。(0 は未定義を表したり、マイナス値は正規の値であることを想定)
    /// </summary>
    public static TEnum ChoicePrompt<TEnum>(PSHostUserInterface ui,
                                            string caption = "",
                                            string message = "")
        where TEnum : struct, Enum
    {
        var labels = Enum.GetValues<TEnum>()
                         .Where(static val => val is > 0)
                         .Select(static val => $"{val}")
                         .ToArray();
        var result = ChoicePrompt(ui, labels, caption, message);
        return Enum.Parse<TEnum>(result);
    }
}
