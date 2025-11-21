import { i18n } from "../i18n/translation";
import I18nKey from "../i18n/i18nKey";

/**
 * 类型图标映射
 */
export const getTypeIcon = (type: string): string => {
    switch (type) {
        case "education":
            return "material-symbols:school";
        case "work":
            return "material-symbols:work";
        case "project":
            return "material-symbols:code";
        case "achievement":
            return "material-symbols:emoji-events";
        default:
            return "material-symbols:event";
    }
};

/**
 * 格式化日期
 */
export const formatDate = (dateString: string): string => {
    const date = new Date(dateString);
    return date.toLocaleDateString("zh-CN", { year: "numeric", month: "long" });
};

/**
 * 计算持续时间
 */
export const getDuration = (startDate: string, endDate?: string): string => {
    const start = new Date(startDate);
    const end = endDate ? new Date(endDate) : new Date();
    const diffTime = Math.abs(end.getTime() - start.getTime());
    const diffMonths = Math.ceil(diffTime / (1000 * 60 * 60 * 24 * 30));

    if (diffMonths < 12) {
        return `${diffMonths} ${i18n(I18nKey.timelineMonths)}`;
    } else {
        const years = Math.floor(diffMonths / 12);
        const months = diffMonths % 12;
        if (months === 0) {
            return `${years} ${i18n(I18nKey.timelineYears)}`;
        } else {
            return `${years} ${i18n(I18nKey.timelineYears)} ${months} ${i18n(I18nKey.timelineMonths)}`;
        }
    }
};
