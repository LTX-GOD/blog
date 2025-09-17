---
title: Terminal Configuration
published: 2025-08-04
pinned: false
description: kitty nvim AeroSpace starship
tags: ['shell','mac']
category: 环境配置
licenseName: "MIT"
author: zsm
draft: false
date: 2025-08-04
pubDate: 2025-08-04
---


## 前言

最近看了一些关于终端的视频，心血来潮，所以自己也更新一下我的配置和软件，正好感觉`iterm2`有点老且卡

## kitty

一个印度佬开发的终端模拟器，非常的nb，看了一下，是go&python&c混合开发的，性能也是非常的好，所以这里换成`kitty`.

### 基础配置

```shell
brew install kitty
#选字体，我的字体是github那个+nerd图标自构的，所以这样方便一点
kitten choose-fonts
#选主题
kitty +kitten themes
```

这样操作之后，勉强能看了bro。

### 二次配置

kitty的配置文件在`~/.config/kitty/`下，新建一个`kitty.conf`，不知道为什么我的主题没有导入进去，自己手写一下

> include dark-theme.auto.conf

然后配置一下字体大小、光标样式、边框、背景透明度、毛玻璃效果、顶部样式，因为我是mac，还要打开mac的键盘映射(option)

```conf
# font
font_size 12
# font_family          Monaspace Radon
disable_ligatures never
cursor_shape beam
# window
hide_window_decorations        titlebar-only
window_padding_width           10
window_border_width            0.5pt
draw_minimal_borders           yes

background_opacity             0.8
background_blur                64
remember_window_size           yes

# tab bar
tab_bar_edge                top
tab_bar_style               powerline
tab_powerline_style         slanted

# general key mapping
macos_option_as_alt yes
```

kitty还有一个巨帅的东西，光标动画

> cursor_trail 3

然后再略微配置一下快捷键映射，这边`iterm2`用多了，改一下

```conf
enabled_layouts splits
enable_audio_bell no

# 跳到行开头和结尾
map cmd+left send_text all \x01
map cmd+right send_text all \x05

# 跳转标签
map cmd+1 goto_tab 1
map cmd+2 goto_tab 2
map cmd+3 goto_tab 3
map cmd+4 goto_tab 4
map cmd+5 goto_tab 5
map cmd+6 goto_tab 6
map cmd+7 goto_tab 7
map cmd+8 goto_tab 8
map cmd+9 goto_tab 9
```

目前这样就够用了，如果有其他的后面再补吧

## AeroSpace

一个窗口平铺管理软件，个人感受比`yabai`好，配置不算繁杂，手风琴模式对我这种小屏幕用户很友好，我的配置大多数是从[帕特里柯基](https://space.bilibili.com/846392?spm_id_from=333.337.search-card.all.click)上面扒下来的

## starship

因为p10k总有一些稀奇古怪的bug，并且缓存机制卡卡的，这里换成starship，配置可以去dis上面自己找找，这里我的配置就是扒下来然后自己改改的

```toml
"$schema" = 'https://starship.rs/config-schema.json'

add_newline = false

command_timeout = 2000

format = """
$os\
$username\
$directory\
$git_branch\
$git_commit\
$git_status\
$git_metrics\
$git_state\
$c\
$rust\
$golang\
$nodejs\
$php\
$java\
$kotlin\
$haskell\
$python\
$package\
$docker_context\
$kubernetes\
$shell\
$container\
$jobs\
${custom.memory_usage}\
${custom.battery}\
${custom.keyboard_layout}\
$time\
$cmd_duration\
$status\
$line_break\
$character\
"""

palette = 'default'

[palettes.default]

color_ok = 'bright-green'
color_danger = 'bright-red'
color_caution = 'bright-yellow'

color_os = 'red'
color_username = 'red'
color_directory = 'yellow'
color_git = 'cyan'
color_git_added = 'bright-green'
color_git_deleted = 'bright-red'
color_env = 'blue'
color_kubernetes = 'purple'
color_docker = 'blue'
color_shell = ''
color_container = ''
color_other = ''
color_time = ''
color_duration = ''

color_vimcmd_ok = 'green'
color_vimcmd_replace = 'purple'
color_vimcmd_visual = 'yellow'

[palettes.gruvbox_dark]

color_ok = '#b8bb26'
color_danger = '#fb4934'
color_caution = '#d79921'

color_os = '#d65d0e'
color_username = '#d65d0e'
color_directory = '#d79921'
color_git = '#689d6a'
color_git_added = '#b8bb26'
color_git_deleted = '#fb4934'
color_env = '#458588'
color_kubernetes = '#b16286'
color_docker = '#458588'
color_shell = '#a89984'
color_container = '#cc241d'
color_other = '#d5c4a1'
color_time = '#fbf1c7'
color_duration = '#fbf1c7'

color_vimcmd_ok = '#8ec07c'
color_vimcmd_replace = '#b16286'
color_vimcmd_visual = '#d79921'

[palettes.gruvbox_light]

color_ok = '#79740e'
color_danger = '#9d0006'
color_caution = '#d79921'

color_os = '#d65d0e'
color_username = '#d65d0e'
color_directory = '#d79921'
color_git = '#689d6a'
color_git_added = '#79740e'
color_git_deleted = '#9d0006'
color_env = '#458588'
color_kubernetes = '#b16286'
color_docker = '#458588'
color_shell = '#7c6f64'
color_container = '#cc241d'
color_other = '#504945'
color_time = '#282828'
color_duration = '#282828'

color_vimcmd_ok = '#689d6a'
color_vimcmd_replace = '#b16286'
color_vimcmd_visual = '#d79921'

[os]
disabled = false
style = "fg:color_os"
format = '[$symbol]($style)'

[os.symbols]
Windows = "󰍲"
Ubuntu = "󰕈"
SUSE = ""
Raspbian = "󰐿"
Mint = "󰣭"
Macos = "󰀵"
Manjaro = ""
Linux = "󰌽"
Gentoo = "󰣨"
Fedora = "󰣛"
Alpine = ""
Amazon = ""
Android = ""
Arch = "󰣇"
Artix = "󰣇"
EndeavourOS = ""
CentOS = ""
Debian = "󰣚"
Redhat = "󱄛"
RedHatEnterprise = "󱄛"
Pop = ""

[username]
show_always = true
style_user = "fg:color_username"
style_root = "bold fg:color_danger"
format = '[ $user ]($style)'

[directory]
style = "fg:color_directory"
read_only_style = "fg:color_directory"
repo_root_style = "bold fg:color_directory"
format = "[ $path ]($style)"
read_only = " "
home_symbol = "~"
truncation_symbol = "…/"
truncation_length = 0
truncate_to_repo = true
fish_style_pwd_dir_length = 0
use_logical_path = true

[git_branch]
symbol = ""
style = "fg:color_git"
format = '\[[$symbol$branch]($style)\]'
only_attached = true
ignore_branches = []
truncation_length = 25
truncation_symbol = "..."
always_show_remote = false
disabled = false

[git_commit]
style = "fg:color_git"
format = "( [($tag)(@$hash)]($style) )"
commit_hash_length = 7
only_detached = true
tag_symbol = "󰓼 "
tag_disabled = false
disabled = false

[git_status]
style = "fg:color_git"
format = '([$ahead_behind]($style) )([$all_status]($style) )'
stashed = "*${count}"
ahead = "⇡${count}"
behind = "⇣${count}"
up_to_date = ""
diverged = "⇡${ahead_count}⇣${behind_count}"
conflicted = "=${count}"
deleted = "×${count}"
renamed = "»${count}"
modified = "!${count}"
staged = "+${count}"
untracked = "?${count}"
ignore_submodules = false
disabled = false

[git_metrics]
format = '([([+$added]($added_style))([-$deleted]($deleted_style))](fg:color_git) )'
added_style = "fg:color_git_added"
deleted_style = "fg:color_git_deleted"
only_nonzero_diffs = true
disabled = false

[git_state]
style = "fg:color_danger"
format = '([$state( $progress_current/$progress_total)]($style bold) )'
rebase = "REBASING"
merge = "MERGING"
revert = "REVERTING"
cherry_pick = "CHERRY-PICKING"
bisect = "BISECTING"
am = "AM"
am_or_rebase = "AM/REBASE"
disabled = false

[nodejs]
symbol = "⬢"
style = "fg:color_env"
format = '( [$symbol( $version)]($style) )'

[c]
symbol = ""
style = "fg:color_env"
format = '( [$symbol( $version)]($style) )'

[rust]
symbol = "󱘗"
style = "fg:color_env"
format = '( [$symbol( $version)]($style) )'

[golang]
symbol = "󰟓"
style = "fg:color_env"
format = '( [$symbol( $version)]($style) )'

[php]
symbol = ""
style = "fg:color_env"
format = '( [$symbol( $version)]($style) )'

[java]
symbol = ""
style = "fg:color_env"
format = '( [$symbol( $version)]($style) )'

[kotlin]
symbol = ""
style = "fg:color_env"
format = '( [$symbol( $version)]($style) )'

[haskell]
symbol = ""
style = "fg:color_env"
format = '( [$symbol( $version)]($style) )'

[python]
symbol = ""
style = "fg:color_env"
format = '( [$symbol( $version)( $virtualenv)]($style) )'
version_format = '${raw}'

[package]
disabled = false
symbol = "󰏗"
style = "fg:color_env"
format = '( [$symbol( $version)]($style) )'

[docker_context]
symbol = ""
style = "fg:color_docker"
format = '( [$symbol( $context)]($style) )'

[kubernetes]
symbol = "󱃾"
style = "fg:color_kubernetes"
format = '( [($symbol( $cluster))]($style) )'
disabled = false

[shell]
disabled = false
format = '[ ⬢ $indicator ]($style)'
bash_indicator = "bash"
fish_indicator = "fish"
zsh_indicator = "zsh"
powershell_indicator = "powershell"
pwsh_indicator = "pwsh"
ion_indicator = "ion"
elvish_indicator = "elvish"
tcsh_indicator = "tcsh"
xonsh_indicator = "xonsh"
cmd_indicator = "cmd"
nu_indicator = "nu"
unknown_indicator = ""
style = "fg:color_shell"

[container]
style = "fg:color_container"
format = '( [$symbol $name]($style) )'

[jobs]
symbol = "󰒋"
style = "fg:color_other"
format = '( [$symbol( $number)]($style) )'
symbol_threshold = 1
number_threshold = 1

[custom.memory_usage]
command = "starship module memory_usage"
when = '[ "${STARSHIP_COCKPIT_MEMORY_USAGE_ENABLED:-false}" = "true" ]'
shell = "sh"
format = "( $output )"
disabled = false

[memory_usage]
threshold = 0
symbol = "󰓅"
style = "fg:color_other"
format = '( [$symbol( ${ram})]($style) )'
disabled = false

[custom.battery]
command = """
battery_info=$(starship module battery)
if [ -n "$battery_info" ]; then
    percent=$(echo "$battery_info" | grep -o '[0-9]*%' | sed 's/%//')
    if [ "$percent" -le "${STARSHIP_COCKPIT_BATTERY_THRESHOLD:-0}" ]; then
        echo "$battery_info" | sed 's/%%/%/'
    fi
fi
"""
when = '[ "${STARSHIP_COCKPIT_BATTERY_ENABLED:-false}" = "true" ]'
shell = "sh"
format = "( $output )"
disabled = false

[battery]
full_symbol = "󰁹"
charging_symbol = "󰂄"
discharging_symbol = "󰂃"
unknown_symbol = "󰂑"
empty_symbol = "󰂎"
format = '( [$symbol( $percentage)]($style) )'
disabled = false

[[battery.display]]
threshold = 10
style = "bold fg:color_danger"

[[battery.display]]
threshold = 20
style = "fg:color_caution"

[[battery.display]]
threshold = 100
style = "fg:color_other"

[time]
disabled = false
time_format = "%R"
style = "fg:color_time"
format = '( [󰔛 $time]($style) )'

[cmd_duration]
min_time = 2000
format = '( [󱫑 $duration]($style) )'
style = 'fg:color_duration'
show_milliseconds = false
disabled = false

[status]
disabled = false
format = '( [$symbol( $common_meaning)( $signal_name)]($style) )'
map_symbol = true
pipestatus = true
symbol = '󰅙'
success_symbol = ''
not_executable_symbol = '󰂭'
not_found_symbol = '󰍉'
sigint_symbol = '󰐊'
signal_symbol = '󱐋'
style = 'bold fg:color_danger'
recognize_signal_code = true

[line_break]
disabled = false

[character]
disabled = false
success_symbol = '[❯](bold fg:color_ok)'
error_symbol = '[❯](bold fg:color_danger)'
vimcmd_symbol = '[❮](bold fg:color_vimcmd_ok)'
vimcmd_replace_one_symbol = '[❮](bold fg:color_vimcmd_replace)'
vimcmd_replace_symbol = '[❮](bold fg:color_vimcmd_replace)'
vimcmd_visual_symbol = '[❮](bold fg:color_vimcmd_visual)'

[custom.keyboard_layout]
command = """

# Set env variables if you want to use layout aliases (in uppercase)
#     export STARSHIP_COCKPIT_KEYBOARD_LAYOUT_ABC=ENG
#     export STARSHIP_COCKPIT_KEYBOARD_LAYOUT_UKRAINIAN=UKR
#
# Implementations:
#     macOS

if [ "$(uname -s)" = "Darwin" ]; then
        input_source=$(defaults read ~/Library/Preferences/com.apple.HIToolbox.plist AppleCurrentKeyboardLayoutInputSourceID)
        layout_id=$(echo "$input_source" | cut -d '.' -f4)
        layout=$(printenv "STARSHIP_COCKPIT_KEYBOARD_LAYOUT_$(echo "$layout_id" | tr '[:lower:]' '[:upper:]')")
        echo "$layout" || echo "$layout_id"
fi

"""
symbol = "󰌌"
style = "fg:color_other"
format = '( [$symbol $output]($style) )'
when = '[ "${STARSHIP_COCKPIT_KEYBOARD_LAYOUT_ENABLED:-false}" = "true" ]'
shell = "sh"
disabled = false
```

目前用起来的适配型还是很高的

## zinit

安装方法就不写了xd，这里主要看一下插件(记得挂梯子)

```
# 高亮
zinit light zsh-users/zsh-syntax-highlighting
# 补全
zinit light zsh-users/zsh-autosuggestions
zinit light zsh-users/zsh-completions
# 搜索
zinit light zdharma/history-search-multi-word
# ls高亮
source /Users/zsm/.config/color.sh
alias ls='gls --color=auto'
```

ls高亮这个自己找一下就行了，或者是用`eza`替代一下。

然后我顺便写了一下历史规则

```
# History
HISTSIZE=5000
HISTFILE=~/.zsh_history
SAVEHIST=$HISTSIZE
HISTDUP=erase
setopt appendhistory
setopt hist_ignore_space
setopt hist_ignore_all_dups
setopt hist_save_no_dups
setopt hist_ignore_dups
setopt hist_find_no_dups
```

其他的环境变量什么的自己加进去就行了，记得写好注释，要不然回头忘了

## nvim

我想用这个`nvim`很久了xd，这里采用`AstroNvim`作为起点

### render-markdown

写markdown必备的一个插件，这里手动添加到`~/.config/nvim/lua/plugins/`里面

```lua
return
  {
    'MeanderingProgrammer/render-markdown.nvim',
    dependencies = { 'nvim-treesitter/nvim-treesitter', 'echasnovski/mini.nvim' }, -- if you use the mini.nvim suite
    -- dependencies = { 'nvim-treesitter/nvim-treesitter', 'echasnovski/mini.icons' }, -- if you use standalone mini plugins
    -- dependencies = { 'nvim-treesitter/nvim-treesitter', 'nvim-tree/nvim-web-devicons' }, -- if you prefer nvim-web-devicons
    ---@module 'render-markdown'
    ---@type render.md.UserConfig
    opts = {},
    config=function (_,opts)
      require("render-markdown").setup(opts)
    end
}
```

### flash

强大的光标跳转插件，同样添加进去

```lua
return
  {
  "folke/flash.nvim",
  event = "VeryLazy",
  ---@type Flash.Config
  opts = {
      modes={
        search={
          enabled=true,
        },
      },
    },
  -- stylua: ignore
  keys = {
    { "s", mode = { "n", "x", "o" }, function() require("flash").jump() end, desc = "Flash" },
    { "S", mode = { "n", "x", "o" }, function() require("flash").treesitter() end, desc = "Flash Treesitter" },
    { "r", mode = "o", function() require("flash").remote() end, desc = "Remote Flash" },
    { "R", mode = { "o", "x" }, function() require("flash").treesitter_search() end, desc = "Treesitter Search" },
    { "<c-s>", mode = { "c" }, function() require("flash").toggle() end, desc = "Toggle Flash Search" },
  },
}
```

### community

一个社区插件，可以直接下载astro社区里面的插件，先用用

```lua
return {
  -- Add the community repository of plugin specifications
  "AstroNvim/astrocommunity",
  -- example of importing a plugin
  -- available plugins can be found at https://github.com/AstroNvim/astrocommunity
  { import = "astrocommunity.colorscheme.catppuccin" },
  { import = "astrocommunity.completion.copilot-lua" },
  -- example of importing an entire language pack
  -- these packs can set up things such as Treesitter, Language Servers, additional language specific plugins, and more!
  { import = "astrocommunity.pack.rust" },
  { import = "astrocommunity.pack.python" },
  { import = "astrocommunity.pack.go"},
}
```

## 最后

目前这些是够用的，`yazi`还没有额外配置，后面会加进来。
