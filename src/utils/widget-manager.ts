import { sidebarLayoutConfig } from "../config";
import type {
	WidgetComponentConfig,
	WidgetComponentType,
} from "../types/config";

// 启用的组件列表，按 order 排序。配置在构建期为常量，导入时计算一次即可。
const enabled = sidebarLayoutConfig.components
	.filter((component) => component.enable)
	.sort((a, b) => a.order - b.order);

/** 根据位置获取组件列表 */
export function getComponentsByPosition(
	position: "top" | "sticky",
): WidgetComponentConfig[] {
	return enabled.filter((component) => component.position === position);
}

/** 获取组件的动画延迟时间（ms） */
export function getAnimationDelay(
	component: WidgetComponentConfig,
	index: number,
): number {
	if (component.animationDelay !== undefined) {
		return component.animationDelay;
	}
	if (sidebarLayoutConfig.defaultAnimation.enable) {
		return (
			sidebarLayoutConfig.defaultAnimation.baseDelay +
			index * sidebarLayoutConfig.defaultAnimation.increment
		);
	}
	return 0;
}

/** 获取组件的 CSS 类名（含响应式隐藏类） */
export function getComponentClass(component: WidgetComponentConfig): string {
	const classes: string[] = [];

	if (component.class) {
		classes.push(component.class);
	}

	if (component.responsive?.hidden) {
		component.responsive.hidden.forEach((device) => {
			switch (device) {
				case "mobile":
					classes.push("hidden", "md:block");
					break;
				case "tablet":
					classes.push("md:hidden", "lg:block");
					break;
				case "desktop":
					classes.push("lg:hidden");
					break;
			}
		});
	}

	return classes.join(" ");
}

/** 获取组件的内联样式（含动画延迟） */
export function getComponentStyle(
	component: WidgetComponentConfig,
	index: number,
): string {
	const styles: string[] = [];

	if (component.style) {
		styles.push(component.style);
	}

	const animationDelay = getAnimationDelay(component, index);
	if (animationDelay > 0) {
		styles.push(`animation-delay: ${animationDelay}ms`);
	}

	return styles.join("; ");
}

/** 检查组件是否应该折叠 */
export function isCollapsed(
	component: WidgetComponentConfig,
	itemCount: number,
): boolean {
	if (!component.responsive?.collapseThreshold) {
		return false;
	}
	return itemCount >= component.responsive.collapseThreshold;
}

/** 检查当前设备是否应该显示侧边栏 */
export function shouldShowSidebar(
	deviceType: "mobile" | "tablet" | "desktop",
): boolean {
	if (!sidebarLayoutConfig.enable) {
		return false;
	}
	return sidebarLayoutConfig.responsive.layout[deviceType] === "sidebar";
}

/** 获取设备断点配置 */
export function getBreakpoints() {
	return sidebarLayoutConfig.responsive.breakpoints;
}

/** 根据组件类型获取组件配置 */
export function getComponentConfig(
	componentType: WidgetComponentType,
): WidgetComponentConfig | undefined {
	return sidebarLayoutConfig.components.find((c) => c.type === componentType);
}

/** 检查组件是否启用 */
export function isComponentEnabled(componentType: WidgetComponentType): boolean {
	return getComponentConfig(componentType)?.enable ?? false;
}
