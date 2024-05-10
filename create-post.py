date = input("Date: ")
title = input("Title: ")
category = str.join(', ', input("Categories (, ): ").split(", "))
filename = date + "-" + title.lower().replace(" ", "-") + ".md"

with open(f"_posts/{filename}", "w") as f:
    f.writelines([
        "---\n",
        f"layout: post\n",
        f"category: [{category}]\n",
        "---\n",
        f"\n# {title}\n",
    ])
    f.close()
    print("OK")