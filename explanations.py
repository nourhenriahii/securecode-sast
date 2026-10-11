"""Plain-language explanations for each SecureCode rule.

Each entry: rule -> language -> (title, what it means, how to fix).
No AI involved: these are fixed texts written for non-experts.
"""

EXPLANATIONS = {
    "hardcoded-credential": {
        "en": ("Secret written in the code",
               "A password or API key is written directly in the code. Anyone who can read the file "
               "(or the GitHub repository) can steal it and use your account.",
               "Move it to an environment variable or a .env file listed in .gitignore. "
               "Revoke the exposed key and create a new one."),
        "ar": ("سر مكتوب داخل الكود",
               "كلمة سر أو مفتاح API مكتوب مباشرة داخل الكود. أي شخص يستطيع قراءة الملف "
               "(أو مستودع GitHub) يستطيع سرقته واستعمال حسابك.",
               "انقله إلى متغيّر بيئة أو ملف .env مضاف إلى .gitignore. "
               "ألغِ المفتاح المكشوف وأنشئ مفتاحًا جديدًا."),
    },
    "known-token-format": {
        "en": ("Access token with a known format",
               "A string that looks like a real access token (for example a Groq, OpenAI-style, GitHub, "
               "Slack or Google key) is in the file, even if the variable has an unusual name. "
               "Anyone who can read the file can use it.",
               "Revoke the token in the provider's console, create a new one, and load it from an "
               "environment variable. Keep the file out of Git."),
        "ar": ("مفتاح وصول بصيغة معروفة",
               "نص يشبه مفتاح وصول حقيقي (مثل مفاتيح Groq أو OpenAI أو GitHub أو Slack أو Google) "
               "موجود في الملف، حتى لو كان اسم المتغيّر غير معتاد. أي شخص يقرأ الملف يستطيع استعماله.",
               "ألغِ المفتاح من لوحة المزوّد وأنشئ مفتاحًا جديدًا، واقرأه من متغيّر بيئة. "
               "أبعد الملف عن Git."),
    },
    "aws-access-key": {
        "en": ("AWS key exposed",
               "An AWS access key is in the code. Attackers scan GitHub for these within minutes "
               "and can run expensive services on your account.",
               "Deactivate the key in the AWS console, create a new one, and load it from the environment."),
        "ar": ("مفتاح AWS مكشوف",
               "مفتاح وصول AWS موجود في الكود. المهاجمون يفحصون GitHub بحثًا عن هذه المفاتيح خلال دقائق "
               "ويمكنهم تشغيل خدمات مكلفة على حسابك.",
               "عطّل المفتاح من لوحة AWS وأنشئ مفتاحًا جديدًا، واقرأه من متغيّرات البيئة."),
    },
    "private-key": {
        "en": ("Private key in the project",
               "A private key is stored in the project. Whoever has it can impersonate your server "
               "or decrypt protected traffic.",
               "Remove it from the repository, generate a new key pair, and keep keys outside the project "
               "(for example in a secret manager)."),
        "ar": ("مفتاح خاص داخل المشروع",
               "مفتاح خاص (Private key) مخزّن داخل المشروع. من يملكه يستطيع انتحال هويّة خادمك "
               "أو فكّ تشفير الاتصالات المحميّة.",
               "احذفه من المستودع، وولّد زوج مفاتيح جديدًا، وأبقِ المفاتيح خارج المشروع "
               "(مثلًا في مدير أسرار)."),
    },
    "dangerous-exec": {
        "en": ("Running text as code (eval/exec)",
               "eval() and exec() run text as if it were code. If any part of that text comes from a user, "
               "they can run their own commands on your machine.",
               "Avoid eval/exec. For data use json.loads or ast.literal_eval; for logic use normal "
               "functions or a lookup table."),
        "ar": ("تنفيذ نص كأنه كود (eval/exec)",
               "الدالتان eval() وexec() تنفّذان نصًا كأنه كود. إذا جاء جزء من هذا النص من مستخدم، "
               "يستطيع تنفيذ أوامره الخاصة على جهازك.",
               "تجنّب eval/exec. للبيانات استعمل json.loads أو ast.literal_eval، وللمنطق استعمل "
               "دوال عادية أو جدول بحث."),
    },
    "shell-true": {
        "en": ("Shell command injection risk",
               "shell=True hands the command to the system shell. Input such as '; rm -rf ~' can add "
               "extra commands (command injection).",
               "Pass the command as a list and drop shell=True: subprocess.run(['ls', folder])."),
        "ar": ("خطر حقن أوامر النظام",
               "الخيار shell=True يمرّر الأمر إلى صدفة النظام. مدخل مثل '; rm -rf ~' "
               "يمكنه إضافة أوامر أخرى (حقن أوامر).",
               "مرّر الأمر كقائمة وأزل shell=True: subprocess.run(['ls', folder])."),
    },
    "sql-injection": {
        "en": ("SQL Injection",
               "The SQL query is built by joining strings with user data. An attacker can change the query "
               "to read, modify or delete the whole database.",
               "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = ?', (name,))."),
        "ar": ("حقن SQL (SQL Injection)",
               "استعلام SQL مبني بدمج نصوص مع بيانات المستخدم. يستطيع المهاجم تغيير الاستعلام "
               "لقراءة قاعدة البيانات كاملة أو تعديلها أو حذفها.",
               "استعمل الاستعلامات المُحدَّدة المعاملات: "
               "cursor.execute('SELECT * FROM users WHERE name = ?', (name,))."),
    },
    "unsafe-deserialization": {
        "en": ("Unsafe pickle loading",
               "pickle can run code while loading a file. Loading a pickle from an untrusted source "
               "can give an attacker control of your machine.",
               "Only load pickle files you created yourself. For shared data use JSON."),
        "ar": ("تحميل pickle غير آمن",
               "مكتبة pickle قد تنفّذ كودًا أثناء تحميل الملف. تحميل pickle من مصدر غير موثوق "
               "قد يعطي المهاجم السيطرة على جهازك.",
               "حمّل فقط ملفات pickle التي أنشأتها بنفسك. للبيانات المشتركة استعمل JSON."),
    },
    "os-system": {
        "en": ("Shell command via os.system",
               "os.system/os.popen run a shell command. If the text includes user input, "
               "it can be abused to run other commands.",
               "Use subprocess.run([...]) with a list of arguments and no shell."),
        "ar": ("أمر نظام عبر os.system",
               "الدالتان os.system/os.popen تنفّذان أمر صدفة. إذا احتوى النص على مدخلات المستخدم، "
               "يمكن استغلاله لتنفيذ أوامر أخرى.",
               "استعمل subprocess.run([...]) مع قائمة وسائط ودون صدفة."),
    },
    "debug-mode": {
        "en": ("Debug mode enabled",
               "Debug mode exposes an interactive debugger. On a reachable server it lets attackers "
               "run code.",
               "Set debug=False in production, or read it from an environment variable."),
        "ar": ("وضع التصحيح (debug) مفعّل",
               "وضع التصحيح يكشف مُنقِّحًا تفاعليًا. على خادم يمكن الوصول إليه، يسمح للمهاجمين "
               "بتنفيذ كود.",
               "اجعل debug=False في الإنتاج، أو اقرأه من متغيّر بيئة."),
    },
    "bind-all-interfaces": {
        "en": ("Server open to the whole network",
               "The server listens on 0.0.0.0, so every device on the same network can reach it, "
               "not only your computer.",
               "Use 127.0.0.1 if only you need it. If it must be reachable, require a strong token "
               "and use HTTPS or a VPN."),
        "ar": ("الخادم مفتوح لكل الشبكة",
               "الخادم يستمع على 0.0.0.0، فيستطيع أي جهاز في نفس الشبكة الوصول إليه "
               "وليس جهازك فقط.",
               "استعمل 127.0.0.1 إذا كنت وحدك من يحتاجه. وإذا لزم الوصول إليه فاشترط token قويًا "
               "واستعمل HTTPS أو VPN."),
    },
    "applescript-injection": {
        "en": ("AppleScript injection",
               "An AppleScript is built from text with unescaped values. A crafted value can break out "
               "of the quotes and run extra commands (for example 'do shell script').",
               "Escape every value (backslashes and quotes) before inserting it, or pass values as "
               "arguments instead of building the script from strings."),
        "ar": ("حقن أوامر AppleScript",
               "سكربت AppleScript مبني من نص يحتوي قيمًا غير مُهرَّبة. قيمة مصمَّمة بعناية قد تخرج "
               "من علامات الاقتباس وتنفّذ أوامر إضافية (مثل 'do shell script').",
               "هرِّب كل قيمة (الشرطة المائلة وعلامات الاقتباس) قبل إدخالها، أو مرّر القيم "
               "كوسائط بدل بناء السكربت من نصوص."),
    },
    "applescript-escaped": {
        "en": ("AppleScript values escaped (verify)",
               "Values are escaped before going into AppleScript, which is good. This is only a reminder "
               "to verify that the escape function is correct.",
               "Check that escape() handles both backslash and double quote, and add a test with "
               "malicious input."),
        "ar": ("قيم AppleScript مُهرَّبة (تحقّق)",
               "القيم تُهرَّب قبل دخولها إلى AppleScript وهذا جيّد. هذا مجرد تذكير للتأكد "
               "من صحّة دالة التهريب.",
               "تأكد أن escape() تعالج الشرطة المائلة وعلامة الاقتباس المزدوجة، وأضف اختبارًا "
               "بمدخلات خبيثة."),
    },
}

LABELS = {
    "en": {
        "title": "SecureCode Security Report",
        "scanned": "Scanned",
        "total": "Total findings",
        "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low",
        "what": "What it means",
        "fix": "How to fix",
        "hint": "Start with the High findings.",
        "none": "No findings. This does not prove the code is safe: the scanner only knows a limited set of patterns.",
        "note": "Automated results can include false positives. Review each finding manually.",
        "ai_title": "AI analysis (a suggestion, verify manually)",
        "verdict_likely_real": "Likely a real problem",
        "verdict_likely_false_positive": "Likely a false positive",
        "verdict_unsure": "Unsure",
        "ai_fix": "Suggested fix",
        "ai_not_sent": "Not sent to the AI (.env file or private key).",
        "ai_suggestions_title": "AI suggestions (not confirmed by the rules)",
        "ai_suggestions_note": "These may be wrong or incomplete. Verify each one manually before acting.",
    },
    "ar": {
        "title": "تقرير SecureCode الأمني",
        "scanned": "المسار المفحوص",
        "total": "عدد النتائج",
        "HIGH": "عالية", "MEDIUM": "متوسطة", "LOW": "منخفضة",
        "what": "ماذا يعني",
        "fix": "كيف تُصلحه",
        "hint": "ابدأ بإصلاح النتائج ذات الخطورة العالية.",
        "none": "لا توجد نتائج. هذا لا يثبت أن الكود آمن: الأداة تعرف عددًا محدودًا من الأنماط فقط.",
        "note": "قد تحتوي النتائج الآلية على إنذارات خاطئة. راجع كل نتيجة يدويًا.",
        "ai_title": "تحليل الذكاء الاصطناعي (اقتراح، تحقّق منه يدويًا)",
        "verdict_likely_real": "غالبًا مشكلة حقيقية",
        "verdict_likely_false_positive": "غالبًا إنذار خاطئ",
        "verdict_unsure": "غير متأكد",
        "ai_fix": "الإصلاح المقترح",
        "ai_not_sent": "لم يُرسَل إلى الذكاء الاصطناعي (ملف .env أو مفتاح خاص).",
        "ai_suggestions_title": "اقتراحات الذكاء الاصطناعي (غير مؤكَّدة بالقواعد)",
        "ai_suggestions_note": "قد تكون خاطئة أو ناقصة. تحقّق من كل اقتراح يدويًا قبل العمل به.",
    },
}
