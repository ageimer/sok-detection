// needs unisim/service/http_server/embedded_script.js

GUI.prototype.on_load = function()
{
	if(activity)
	{
		var own_tab = this.find_own_tab();
		if(own_tab)
		{
			own_tab.scroll_to_bottom();
		}
	}
}

var gui = new GUI();
