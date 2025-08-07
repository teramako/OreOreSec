using System.Management.Automation.Host;
using System.Security;

namespace MT.PowerShell;

public static class UI
{
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

    public static TEnum ChoicePrompt<TEnum>(PSHostUserInterface ui,
                                            string caption = "",
                                            string message = "")
        where TEnum : struct, Enum
    {
        var labels = Enum.GetNames<TEnum>();
        var result = ChoicePrompt(ui, labels, caption, message);
        return Enum.Parse<TEnum>(result);
    }
}
