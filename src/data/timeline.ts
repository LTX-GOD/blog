// Timeline data configuration file
// Used to manage data for the timeline page

export interface TimelineItem {
	id: string;
	title: string;
	description: string;
	type: "education" | "work" | "project" | "achievement";
	startDate: string;
	endDate?: string; // If empty, it means current
	location?: string;
	organization?: string;
	position?: string;
	skills?: string[];
	achievements?: string[];
	links?: {
		name: string;
		url: string;
		type: "website" | "certificate" | "project" | "other";
	}[];
	icon?: string; // Iconify icon name
	color?: string;
	featured?: boolean;
}

export const timelineData: TimelineItem[] = [
	{
		id: "mindunbei-2025",
		title: "2025 闽盾杯",
		description: "No.13",
		type: "achievement",
		startDate: "2025-09-06",
		icon: "material-symbols:emoji-events",
		color: "#7C3AED",
	},
	{
		id: "lilctf-2025",
		title: "2025 LilCTF",
		description: "No.18（三等奖）",
		type: "achievement",
		startDate: "2025-08-17",
		icon: "material-symbols:emoji-events",
		color: "#7C3AED",
	},
	{
		id: "industrial-2025",
		title: "第九届工业信息安全技能大赛密码应用安全锦标赛",
		description: "优秀奖（个人奖）",
		type: "achievement",
		startDate: "2025-07-25",
		icon: "material-symbols:emoji-events",
		color: "#7C3AED",
	},
	{
		id: "mocsctf-2025",
		title: "2025 MOCSCTF",
		description: "No.2",
		type: "achievement",
		startDate: "2025-07-13",
		icon: "material-symbols:emoji-events",
		color: "#7C3AED",
	},
	{
		id: "xuanyuanbei-2025",
		title: "2025 第一届“轩辕杯”",
		description: "No.3 (一等奖)",
		type: "achievement",
		startDate: "2025-05-21",
		icon: "material-symbols:emoji-events",
		color: "#7C3AED",
	},
	{
		id: "sssc-east-ad-2025",
		title: "第十八届软件系统安全赛-攻防赛道-华东赛区",
		description: "二等奖",
		type: "achievement",
		startDate: "2025-03-23",
		icon: "material-symbols:emoji-events",
		color: "#7C3AED",
	},
	{
		id: "changchengbei-2025",
		title: "第十八届全国大学生信息安全竞赛暨第二届“长城杯”铁人三项赛（防护赛）半决赛",
		description: "三等奖",
		type: "achievement",
		startDate: "2025-03-16",
		icon: "material-symbols:emoji-events",
		color: "#7C3AED",
	},
	{
		id: "qihangbei-2025",
		title: "第一届“启航杯”网络安全挑战赛",
		description: "No.1",
		type: "achievement",
		startDate: "2025-01-25",
		icon: "material-symbols:emoji-events",
		color: "#7C3AED",
	},

	// 2024 年
	{
		id: "cnfnstctf-2024",
		title: "第二届 CN-fnst::CTF",
		description: "二等奖",
		type: "achievement",
		startDate: "2024-12-22",
		icon: "material-symbols:emoji-events",
		color: "#059669",
	},
	{
		id: "wubei-2024",
		title: "第一届“吾杯”网络安全技能大赛",
		description: "一等奖",
		type: "achievement",
		startDate: "2024-12-06",
		icon: "material-symbols:emoji-events",
		color: "#059669",
	},
	{
		id: "hkcert-2024",
		title: "2024 HKcert CTF",
		description: "No.26",
		type: "achievement",
		startDate: "2024-11-10",
		icon: "material-symbols:emoji-events",
		color: "#059669",
	},
	{
	id: "aibianma-2024",
	title: "河南爱编码有限公司",
	description: "任职期间参与前端开发工作",
	type: "work",
	startDate: "2024-07-19",
	endDate: "2024-09-01",
	position: "python讲师",
	location: "河南",
	skills: ["python", "oi", "数论"],
	achievements: [
		"参与公司课程的开发",
		"讲授python和数论在oi的作用",
		],
	icon: "material-symbols:work",
	color: "#DC2626",
},

];

// Get timeline statistics
export const getTimelineStats = () => {
	const total = timelineData.length;
	const byType = {
		education: timelineData.filter((item) => item.type === "education").length,
		work: timelineData.filter((item) => item.type === "work").length,
		project: timelineData.filter((item) => item.type === "project").length,
		achievement: timelineData.filter((item) => item.type === "achievement")
			.length,
	};

	return { total, byType };
};

// Get timeline items by type
export const getTimelineByType = (type?: string) => {
	if (!type || type === "all") {
		return timelineData.sort(
			(a, b) =>
				new Date(b.startDate).getTime() - new Date(a.startDate).getTime(),
		);
	}
	return timelineData
		.filter((item) => item.type === type)
		.sort(
			(a, b) =>
				new Date(b.startDate).getTime() - new Date(a.startDate).getTime(),
		);
};

// Get featured timeline items
export const getFeaturedTimeline = () => {
	return timelineData
		.filter((item) => item.featured)
		.sort(
			(a, b) =>
				new Date(b.startDate).getTime() - new Date(a.startDate).getTime(),
		);
};

// Get current ongoing items
export const getCurrentItems = () => {
	return []
};

// Calculate total work experience
export const getTotalWorkExperience = () => {
	const workItems = timelineData.filter((item) => item.type === "work");
	let totalMonths = 0;

	workItems.forEach((item) => {
		const startDate = new Date(item.startDate);
		const endDate = item.endDate ? new Date(item.endDate) : new Date();
		const diffTime = Math.abs(endDate.getTime() - startDate.getTime());
		const diffMonths = Math.ceil(diffTime / (1000 * 60 * 60 * 24 * 30));
		totalMonths += diffMonths;
	});

	return {
		years: Math.floor(totalMonths / 12),
		months: totalMonths % 12,
	};
};
