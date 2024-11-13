document.addEventListener("DOMContentLoaded", function() {
    const select = document.getElementById("options");
    const datePicker = document.getElementById("date-picker");
    const dateInput = document.getElementById("date");
    const result = document.getElementById("result");
    const timeSlots = document.getElementById("time-slots");
    const resetButton = document.getElementById("reset-button");

    select.addEventListener("change", function() {
        const selectedOption = select.options[select.selectedIndex].text;
        if (selectedOption !== "教室") {
            datePicker.style.display = "block"; // 顯示日期選擇器
            result.innerHTML = `你選擇了：${selectedOption}`;
            dateInput.value = ""; // 重置日期選擇器
            dateInput.disabled = false; // 啟用日期選擇器
            timeSlots.style.display = "none"; // 隱藏時間表
        } else {
            datePicker.style.display = "none"; // 隱藏日期選擇器
            timeSlots.style.display = "none"; // 隱藏時間表
            result.innerHTML = ""; // 清空結果
        }
    });

    dateInput.addEventListener("change", function() {
        const selectedDate = dateInput.value;
        result.innerHTML += `，日期：${selectedDate}`;
        dateInput.disabled = true; // 禁用日期選擇器
        showTimeSlots(); // 顯示時間表
    });

    function showTimeSlots() {
        const timeSlotsHtml = `
            <h3>選擇時間段：</h3>
            <button class="time-slot">08:00 - 10:00</button>
            <button class="time-slot">10:00 - 12:00</button>
            <button class="time-slot">12:00 - 14:00</button>
            <button class="time-slot">14:00 - 16:00</button>
            <button class="time-slot">16:00 - 18:00</button>
            <button class="time-slot">18:00 - 20:00</button>
        `;
        timeSlots.innerHTML = timeSlotsHtml;
        timeSlots.style.display = "block"; // 顯示時間表

        const buttons = timeSlots.querySelectorAll(".time-slot");
        buttons.forEach(button => {
            button.addEventListener("click", function() {
                result.innerHTML += `，時間段：${button.innerText}`;
                buttons.forEach(btn => btn.disabled = true); // 禁用所有按鈕
                resetButton.style.display = "block"; // 顯示重新選擇時段按鈕
            });
        });
    }
    resetButton.addEventListener("click", function() {
        const buttons = timeSlots.querySelectorAll(".time-slot");
        buttons.forEach(button => button.disabled = false); // 啟用所有按鈕
        result.innerHTML = result.innerHTML.split('，時間段：')[0]; // 移除時間段信息
        resetButton.style.display = "none"; // 隱藏重新選擇時段按鈕
    });
});
function onClick(e) {
    e.preventDefault();
    grecaptcha.enterprise.ready(async () => {
      const token = await grecaptcha.enterprise.execute('6LcdGnwqAAAAAHmFRTHmL0xUx4Ac_1PQBReIK74Q', {action: 'LOGIN'});
    });
  }