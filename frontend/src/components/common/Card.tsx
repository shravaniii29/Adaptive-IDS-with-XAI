import type { ReactNode } from "react";
import clsx from "clsx";

interface CardProps{
children:ReactNode;
className?:string;
}

export default function Card({

children,

className,

}:CardProps){

return(

<div

className={clsx(

"rounded-3xl",

"border",

"border-white/5",

"bg-[#111827]/90",

"backdrop-blur-xl",

"shadow-2xl",

"transition-all",

"duration-300",

"hover:-translate-y-1",

"hover:border-indigo-500/30",

"hover:shadow-indigo-500/10",

"p-6",

className

)}

>

{children}

</div>

);

}
