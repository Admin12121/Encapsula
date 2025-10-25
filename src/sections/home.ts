import { FULL_NAME, ALIAS } from "../data.js";

import CFonts from "cfonts";

export default function showHome() {
  const heading = CFonts.render(FULL_NAME, {
    font: "block",
    align: "left",
    colors: ["#f97316", "#ea580c"],
    background: "transparent",
    letterSpacing: 1,
    lineHeight: 1,
    space: false,
    maxLength: "0",
  });

  if (!heading || typeof heading === "boolean") {
    return "";
  }

  const ascii = `
                                         z
         zX                            zy
           2z                         zz
    o      z A                      A y      o
      D s  z zzA                  A      s
         l yw z  D              i A  A  A
              zzA yA w z      Bz C  z
       zA  z zz  AAXyy  Hzz1  zAk A    zgA
               A  z   cA  zz   A  A
           zA  AvA  zAzzAzA2AAz kAAz A
          yzzz2y   zAzAAqDz0Azzz B 5z zz
             zy zAAz z z  zzzygA  yz
                EAzzAzA zzz9zzgzjz  z
              z  xzzz       zB zz   z
              AzDz zz A   z9  z zxzA
            AAz    zz z Hz   xyzz z BA
                   zA yzs    Az  y
              A     By AI y3
              A        zAw 1A
              9      z AAw 9A
                     z z K Az
                        wlz
                     z  zly z
                         fT
                         y
                         5
  `.trim();

  const result = heading.string;
  return result + "\n" + ALIAS;
}
